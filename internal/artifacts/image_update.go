package artifacts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/xrayver"
	"golang.org/x/sys/unix"
)

const imageRequestFile = "image-update.request"
const legacyImageRequest = "image-update.json"
const imageBootstrapFile = "image-bootstrap.receipt"
const imageProbeFile = "image-probe.request"
const imageWindow = 5 * time.Minute

var (
	ErrImageBusy     = errors.New("artifacts: image replacement pending")
	ErrImageState    = errors.New("artifacts: cannot verify installed image state")
	ErrImagePrevious = errors.New("artifacts: no previously committed image")
)

type imageRequest struct {
	Version         int      `json:"version"`
	InstallationID  string   `json:"installation_id"`
	Component       string   `json:"component"`
	Previous        ImageRef `json:"previous"`
	Candidate       ImageRef `json:"candidate"`
	SelectionDigest string   `json:"selection_digest"`
	Phase           string   `json:"phase"`
	Nonce           string   `json:"nonce"`
	Started         int64    `json:"started"`
	Deadline        int64    `json:"deadline"`
	OfflineRollback bool     `json:"offline_rollback,omitempty"`
}

type imageReceipt struct {
	Version        int      `json:"version"`
	InstallationID string   `json:"installation_id"`
	Active         ImageRef `json:"active"`
	Previous       ImageRef `json:"previous"`
}

type ImageOperation struct {
	Component   string `json:"component"`
	OperationID string `json:"operation_id"`
	From        string `json:"from"`
	To          string `json:"to"`
}
type ImageStatus struct {
	Component string          `json:"component"`
	Active    string          `json:"active"`
	Previous  string          `json:"previous,omitempty"`
	Pending   *ImageOperation `json:"pending,omitempty"`
}

func imageNonce(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (m imageRequest) valid() bool {
	return m.Version == 1 && imageNonce(m.InstallationID) && imageNonce(m.Nonce) && m.Phase == "requested" &&
		m.Started > 0 && m.Deadline > m.Started && m.Deadline-m.Started == int64(imageWindow/time.Second) &&
		isSHA256Hex(m.SelectionDigest) && m.Candidate.Valid() && m.Previous.Valid() &&
		m.Component == m.Candidate.Component && m.Component == m.Previous.Component && m.Candidate.Digest != m.Previous.Digest && m.Candidate.ImageID != m.Previous.ImageID &&
		(!m.OfflineRollback || m.Component == "runner")
}

// The checksum binds a runner proof to the exact active core, config and geo
// that were running before the request. Nothing from the config is copied.
func ImageSelectionDigest(sel runnerapi.Selection) string {
	if sel.Validate() != nil {
		return ""
	}
	b, _ := json.Marshal(sel)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newImageRequest(id string, from, to ImageRef, sel runnerapi.Selection, now time.Time) (imageRequest, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return imageRequest{}, ErrImageState
	}
	m := imageRequest{Version: 1, InstallationID: id, Component: to.Component, Previous: from, Candidate: to, SelectionDigest: ImageSelectionDigest(sel), Phase: "requested", Nonce: hex.EncodeToString(nonce[:]), Started: now.Unix(), Deadline: now.Add(imageWindow).Unix()}
	if !m.valid() {
		return imageRequest{}, ErrImageState
	}
	return m, nil
}

func (m imageRequest) operation() ImageOperation {
	return ImageOperation{Component: m.Component, OperationID: m.Nonce, From: m.Previous.Digest, To: m.Candidate.Digest}
}

func readImageJSON(data, name string, dst any) (bool, error) {
	dir := filepath.Join(data, "state")
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return false, ErrImageState
	}
	b, err := atomicfile.ReadRegular(filepath.Join(dir, name), 4096, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrImageState
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil || dec.Decode(new(any)) != io.EOF {
		return false, ErrImageState
	}
	return true, nil
}

// A malformed or inaccessible marker still fences mutations. Only the owner
// watchdog retires a published request, after healthy recovery/readback.
func ImagePending(data string) bool {
	return imageFilePresent(data, imageRequestFile) || imageFilePresent(data, legacyImageRequest)
}

func imageFilePresent(data, name string) bool {
	_, err := os.Lstat(filepath.Join(data, "state", name))
	return !errors.Is(err, fs.ErrNotExist)
}
func readImageRequest(data, id string) (*imageRequest, error) {
	if imageFilePresent(data, legacyImageRequest) {
		return nil, ErrImageState
	}
	var m imageRequest
	found, err := readImageJSON(data, imageRequestFile, &m)
	if !found || err != nil {
		return nil, err
	}
	if !m.valid() || m.InstallationID != id {
		return nil, ErrImageState
	}
	return &m, nil
}

// Link the fully synced inode into the operation namespace without replacing
// another request, including one whose acknowledgement was lost.
func publishImageRequest(data string, m imageRequest) error {
	if !m.valid() {
		return ErrImageState
	}
	if imageFilePresent(data, legacyImageRequest) {
		return ErrImageBusy
	}
	dir := filepath.Join(data, "state")
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return ErrImageState
	}
	f, err := os.CreateTemp(dir, ".image-request-")
	if err != nil {
		return ErrImageState
	}
	name := f.Name()
	defer os.Remove(name)
	buf, _ := json.Marshal(m)
	_, writeErr := f.Write(buf)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if closeErr := f.Close(); writeErr != nil || closeErr != nil {
		return ErrImageState
	}
	if err = os.Link(name, filepath.Join(dir, imageRequestFile)); errors.Is(err, fs.ErrExist) {
		return ErrImageBusy
	} else if err != nil {
		return ErrImageState
	}
	if atomicfile.SyncDir(dir) != nil {
		return ErrImageState
	}
	return nil
}

func imageVersions(data, id, component string, boot ImageBootstrap) (imageReceipt, error) {
	if !imageNonce(id) || !ValidImageComponent(component) {
		return imageReceipt{}, ErrImageState
	}
	var wire struct {
		Version        int             `json:"version"`
		InstallationID string          `json:"installation_id"`
		Active         ImageRef        `json:"active"`
		Previous       json.RawMessage `json:"previous"`
	}
	found, err := readImageJSON(data, "image-"+component+".receipt", &wire)
	r := imageReceipt{Version: wire.Version, InstallationID: wire.InstallationID, Active: wire.Active}
	if err != nil || !found || r.Version != 1 || r.InstallationID != id || !r.Active.Valid() || r.Active.Component != component || len(wire.Previous) == 0 {
		return imageReceipt{}, ErrImageState
	}
	if bytes.Equal(wire.Previous, []byte("null")) {
		initial := boot.Tikray
		if component == "runner" {
			initial = boot.Runner
		}
		if r.Active != initial {
			return imageReceipt{}, ErrImageState
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(wire.Previous))
		dec.DisallowUnknownFields()
		if dec.Decode(&r.Previous) != nil || !r.Previous.Valid() || r.Previous.Component != component || r.Active.Digest == r.Previous.Digest || r.Active.ImageID == r.Previous.ImageID {
			return imageReceipt{}, ErrImageState
		}
	}
	return r, nil
}

func readImageID(data string) (string, error) {
	b, err := atomicfile.ReadRegular(filepath.Join(data, "state", "install.id"), 32, 0600)
	if err != nil || !imageNonce(string(b)) {
		return "", ErrImageState
	}
	return string(b), nil
}

func ReadImageStatus(data, component string) (ImageStatus, error) {
	boot, err := ReadImageBootstrap(data)
	if err != nil {
		return ImageStatus{}, err
	}
	id, err := readImageID(data)
	if err != nil {
		return ImageStatus{}, err
	}
	r, err := imageVersions(data, id, component, boot)
	if err != nil {
		return ImageStatus{}, err
	}
	result := ImageStatus{Component: component, Active: r.Active.Digest, Previous: r.Previous.Digest}
	m, err := readImageRequest(data, id)
	if err != nil {
		return ImageStatus{}, err
	}
	if m != nil && m.Component == component {
		op := m.operation()
		result.Pending = &op
	}
	return result, nil
}

func (u *CoreUpdater) BeginImageUpdate(ctx context.Context, image VerifiedImage) (ImageOperation, error) {
	op, err := u.beginImageChange(ctx, image.Ref().Component, image.Ref(), false)
	if err != nil {
		// A disconnected caller may still have published its request. Only
		// discard this candidate after checking the live marker and lineage.
		u.DiscardStagedImage(ctx, image)
	}
	return op, err
}

// DiscardStagedImage retires a verified candidate that failed before
// publication, provided it is unreferenced by a live request or receipt.
func (u *CoreUpdater) DiscardStagedImage(ctx context.Context, image VerifiedImage) {
	if !image.Ref().Valid() {
		return
	}
	reclaim, done := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer done()
	u.retireRefusedImage(reclaim, image.Ref())
}

func (u *CoreUpdater) BeginImageRollback(ctx context.Context, component string) (ImageOperation, error) {
	return u.beginImageChange(ctx, component, ImageRef{}, true)
}

func (u *CoreUpdater) beginImageChange(ctx context.Context, component string, target ImageRef, rollback bool) (ImageOperation, error) {
	if !ValidImageComponent(component) || u.Runner == nil {
		return ImageOperation{}, ErrImageState
	}
	unlock, err := lockState(u.stateDir())
	if err != nil {
		return ImageOperation{}, err
	}
	defer unlock()
	if ImagePending(u.Data) {
		return ImageOperation{}, ErrImageBusy
	}
	if GeoPending(u.Data) || HotPending(u.Data) {
		return ImageOperation{}, ErrLocked
	}
	if _, err := os.Lstat(u.candidatePath()); !errors.Is(err, fs.ErrNotExist) {
		return ImageOperation{}, ErrLocked
	}
	boot, err := ReadImageBootstrap(u.Data)
	if err != nil {
		return ImageOperation{}, err
	}
	id, err := readImageID(u.Data)
	if err != nil {
		return ImageOperation{}, err
	}
	r, err := imageVersions(u.Data, id, component, boot)
	if err != nil {
		return ImageOperation{}, err
	}
	if rollback {
		if !r.Previous.Valid() {
			return ImageOperation{}, ErrImagePrevious
		}
		target = r.Previous
	}
	for _, ref := range []ImageRef{r.Active, target} {
		if !ref.Valid() || ref.Component != component {
			return ImageOperation{}, ErrImageState
		}
		if err := VerifyImageRef(ctx, u.Data, ref, boot.Arch); err != nil {
			return ImageOperation{}, err
		}
	}
	if target.Digest == r.Active.Digest || target.ImageID == r.Active.ImageID {
		return ImageOperation{}, errors.New("artifacts: requested image is already active")
	}
	rs, err := u.Runner.Status(ctx)
	var selection runnerapi.Selection
	offlineRollback := false
	if err == nil && rs.State == runnerapi.StateRunning && rs.Active != nil && rs.Candidate == nil && rs.GatewayUp && rs.RoutesOK {
		selection = *rs.Active
	} else if rollback && component == "runner" && (err != nil || (rs.Candidate == nil && rs.State != runnerapi.StateTrial)) {
		selection, err = u.savedImageSelection(ctx)
		if err != nil {
			return ImageOperation{}, err
		}
		// Only this explicit rollback verified the saved selection while
		// the old runner could not prove a working data path.
		offlineRollback = true
	} else {
		return ImageOperation{}, ErrImageState
	}
	m, err := newImageRequest(id, r.Active, target, selection, u.now())
	if err != nil {
		return ImageOperation{}, err
	}
	m.OfflineRollback = offlineRollback
	if err := ctx.Err(); err != nil {
		return ImageOperation{}, err
	}
	// A retained data directory can be reinstalled while release files are
	// verified. Never act on the old identity, key or rollback lineage.
	liveID, e := readImageID(u.Data)
	liveBoot, be := ReadImageBootstrap(u.Data)
	live, re := imageVersions(u.Data, id, component, boot)
	if e != nil || be != nil || re != nil || liveID != id || liveBoot != boot || live != r {
		return ImageOperation{}, ErrImageState
	}
	if err := publishImageRequest(u.Data, m); err != nil {
		return ImageOperation{}, err
	}
	return m.operation(), nil
}

type imageProbe struct {
	Version   int    `json:"version"`
	Nonce     string `json:"nonce"`
	Digest    string `json:"digest"`
	Challenge string `json:"challenge"`
}

func proveRunnerImage(ctx context.Context, data, id string, verify func(context.Context, string) error) error {
	m, err := readImageRequest(data, id)
	if err != nil {
		return err
	}
	if m == nil || m.Component != "runner" {
		return nil
	}
	var p imageProbe
	found, err := readImageJSON(data, imageProbeFile, &p)
	if !found || err != nil {
		return err
	}
	if p.Version != 1 || p.Nonce != m.Nonce || !imageNonce(p.Challenge) || (p.Digest != m.Candidate.Digest && p.Digest != m.Previous.Digest) {
		return ErrImageState
	}
	path := filepath.Join(data, "state", "image-proved")
	want := p.Nonce + " " + p.Digest + " " + p.Challenge
	old, err := atomicfile.ReadRegular(path, 200, 0600)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ErrImageState
	}
	if string(old) == want {
		return nil
	}
	if verify(ctx, m.SelectionDigest) != nil {
		return ErrImageState
	}
	again, err := readImageRequest(data, id)
	if err != nil || again == nil || *again != *m {
		return ErrImageState
	}
	var latest imageProbe
	if ok, err := readImageJSON(data, imageProbeFile, &latest); err != nil || !ok || latest != p {
		return ErrImageState
	}
	if atomicfile.WriteFile(path, []byte(want), 0600) != nil {
		return ErrImageState
	}
	return nil
}

// ProveRunnerImage answers only the owner's pending nonce and challenge.
func ProveRunnerImage(ctx context.Context, data string, verify func(context.Context, string) error) error {
	id, err := readImageID(data)
	if err != nil {
		return err
	}
	return proveRunnerImage(ctx, data, id, verify)
}

// PruneInstalledImages runs under the service writer. Only the two positively
// identified active/previous pairs may establish a keep set. Initial archives
// remain available for an owner re-import.
func PruneInstalledImages(ctx context.Context, data string) error {
	unlock, err := lockState(filepath.Join(data, "state"))
	if err != nil {
		return err
	}
	defer unlock()
	if ImagePending(data) {
		return ErrImageBusy
	}
	_, e := os.Lstat(filepath.Join(data, "state", imageBootstrapFile))
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	boot, err := ReadImageBootstrap(data)
	if err != nil {
		return ErrImageState
	}
	return pruneImagesLocked(ctx, data, boot, nil)
}

// RetainedStateSchemas verifies the two retained control archives rather than
// guessing schema support from a release name or current program version.
func RetainedStateSchemas(ctx context.Context, data string) (int, int, error) {
	unlock, err := lockState(filepath.Join(data, "state"))
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	if ImagePending(data) {
		return 0, 0, ErrImageBusy
	}
	b, err := ReadImageBootstrap(data)
	if err != nil {
		return 0, 0, ErrImageState
	}
	key, err := imageKey(b.Publisher)
	if err != nil {
		return 0, 0, ErrImageState
	}
	dir, err := openGeoDir(data, false, "images")
	if err != nil {
		return 0, 0, ErrImageState
	}
	defer unix.Close(dir)
	lineage, err := verifyRetainedImages(ctx, data, dir, b, key, nil)
	if err != nil {
		return 0, 0, err
	}
	if !lineage.control.Previous.Valid() {
		return 0, 0, nil
	}
	return lineage.refs[lineage.control.Active].StateSchema, lineage.refs[lineage.control.Previous].StateSchema, nil
}

// A failed runner cannot authorize its own rollback. Verify its restart
// selection from disk against the current owner's render, immutable config
// bytes and authenticated installed core. The newly started runner still
// has to pass the ordinary live proof before RouterOS retires this request.
func (u *CoreUpdater) savedImageSelection(ctx context.Context) (runnerapi.Selection, error) {
	var sel runnerapi.Selection
	run, err := openGeoDir(u.Data, false, "run")
	if err != nil {
		return sel, ErrImageState
	}
	defer unix.Close(run)
	var raw bytes.Buffer
	if readGeoFile(run, "active.json", 4096, &raw) != nil || json.Unmarshal(raw.Bytes(), &sel) != nil || sel.Validate() != nil || u.Render == nil {
		return runnerapi.Selection{}, ErrImageState
	}
	v, err := xrayver.Parse(sel.Core)
	if err != nil {
		return runnerapi.Selection{}, ErrImageState
	}
	b, err := u.Render(v, sel.Geo)
	if err != nil || ConfigName(b) != sel.Config || u.verifyConfig(ctx, sel.Config) != nil {
		return runnerapi.Selection{}, ErrImageState
	}
	if sel.Geo != "" {
		if _, _, err := LoadGeo(u.Data, sel.Geo); err != nil {
			return runnerapi.Selection{}, ErrImageState
		}
	}
	slots, err := ListCores(u.coresDir())
	if err != nil {
		return runnerapi.Selection{}, ErrImageState
	}
	for _, s := range slots {
		if s.Meta.Version == sel.Core && (s.Meta.Verified == "dgst" || s.Meta.Verified == "index") && s.VerifyBinary(ctx) == nil {
			return sel, nil
		}
	}
	return runnerapi.Selection{}, ErrImageState
}

// An unreadable request cannot authorize changing the watchdog's temporary
// routing and DNS settings. The native scheduler works without the service.
func HoldsRunnerPolicy(data string) bool {
	if !ImagePending(data) {
		return false
	}
	id, err := readImageID(data)
	if err != nil {
		return true
	}
	m, err := readImageRequest(data, id)
	return err != nil || (m != nil && m.Component == "runner")
}
