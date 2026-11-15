package artifacts

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInterruptedImagePublication(t *testing.T) {
	for _, step := range []string{"before receipt", "after receipt", "after signature", "after archive", "foreign signature"} {
		t.Run(step, func(t *testing.T) {
			u, key := seedInstalledImages(t)
			raw := testImage(t, "runner", u.Arch, "candidate")
			sig := signImageFixture(t, key, raw)
			putInboxImage(t, u, "runner", "candidate", raw, sig)
			slot, err := u.StageImage(t.Context(), "runner", "candidate")
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(u.Data, "images")
			path := filepath.Join(dir, imageFilename(slot.Ref()))
			work := filepath.Join(dir, ".image-stage-cut")
			if os.Mkdir(work, 0700) != nil {
				t.Fatal("fixture directory")
			}
			move := func(from, to string) {
				t.Helper()
				if os.Rename(from, to) != nil {
					t.Fatal("fixture move")
				}
			}
			link := func(from, to string) {
				t.Helper()
				if os.Link(from, to) != nil {
					t.Fatal("fixture link")
				}
			}
			move(path, filepath.Join(work, "archive"))
			move(path+".sig", filepath.Join(work, "archive.sig"))
			move(path+".owned", filepath.Join(work, "publication.json"))
			st, _ := os.Stat(work)
			sys := st.Sys().(*syscall.Stat_t)
			body, _ := json.Marshal(geoWork{Name: filepath.Base(work), Device: uint64(sys.Dev), Inode: sys.Ino})
			if os.WriteFile(filepath.Join(dir, imageWorkFile), body, 0600) != nil {
				t.Fatal("fixture marker")
			}
			if step != "before receipt" {
				link(filepath.Join(work, "publication.json"), path+".owned")
			}
			switch step {
			case "after archive":
				link(filepath.Join(work, "archive"), path)
				fallthrough
			case "after signature":
				link(filepath.Join(work, "archive.sig"), path+".sig")
			case "foreign signature":
				if os.WriteFile(path+".sig", []byte(sig), 0600) != nil {
					t.Fatal("foreign signature fixture")
				}
			}
			priorSig, _ := os.Stat(path + ".sig")
			second, err := u.StageImage(t.Context(), "runner", "candidate")
			if err != nil || second.Ref() != slot.Ref() {
				t.Fatal("could not resume interrupted signed archive publication")
			}
			if err = PruneImages(t.Context(), u.Data, u.Arch, nil); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{work, path, path + ".owned"} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatal("interrupted owned slot remained on disk")
				}
			}
			if step == "foreign signature" {
				after, e := os.Stat(path + ".sig")
				if e != nil || !os.SameFile(priorSig, after) {
					t.Fatal("foreign signature replaced")
				}
			} else if _, e := os.Lstat(path + ".sig"); !os.IsNotExist(e) {
				t.Fatal("interrupted owned signature remained on disk")
			}
		})
	}
}

func TestImageRefusalRetiresOnlyUnselectedCandidate(t *testing.T) {
	for _, condition := range []string{"unhealthy runner", "pending", "damaged lineage"} {
		t.Run(condition, func(t *testing.T) {
			u, key := seedInstalledImages(t)
			stage := func(v string) VerifiedImage {
				t.Helper()
				raw := testImage(t, "runner", u.Arch, v)
				putInboxImage(t, u, "runner", v, raw, signImageFixture(t, key, raw))
				x, e := u.StageImage(t.Context(), "runner", v)
				if e != nil {
					t.Fatal(e)
				}
				return x
			}
			prev, active := stage("v1"), stage("v2")
			id := strings.Repeat("a", 32)
			state := filepath.Join(u.Data, "state")
			receipt, _ := json.Marshal(imageReceipt{1, id, active.Ref(), prev.Ref()})
			if condition == "damaged lineage" {
				receipt = []byte("broken")
			}
			if os.WriteFile(filepath.Join(state, "install.id"), []byte(id), 0600) != nil || os.WriteFile(filepath.Join(state, "image-runner.receipt"), receipt, 0600) != nil {
				t.Fatal("fixture lineage")
			}
			if condition == "pending" && os.WriteFile(filepath.Join(state, imageRequestFile), []byte("ambiguous"), 0600) != nil {
				t.Fatal("fixture marker")
			}
			for _, v := range []string{"v3", "v4"} {
				img := stage(v)
				if _, e := u.BeginImageUpdate(t.Context(), img); e == nil {
					t.Fatal("could not simulate pre-publication refusal")
				}
				path := filepath.Join(u.Data, "images", imageFilename(img.Ref()))
				for _, ext := range []string{"", ".sig", ".owned"} {
					_, e := os.Stat(path + ext)
					if condition == "unhealthy runner" && !os.IsNotExist(e) {
						t.Fatal("refused candidate accumulated outside retention")
					}
					if condition != "unhealthy runner" && e != nil {
						t.Fatal("uncertain pending or lineage lost candidate")
					}
				}
			}
			for _, v := range []VerifiedImage{prev, active} {
				if VerifyImageRef(t.Context(), u.Data, v.Ref(), u.Arch) != nil {
					t.Fatal("retained archive removed")
				}
			}
		})
	}
}

func TestImageRetentionWithUnsettledOwnership(t *testing.T) {
	for _, condition := range []string{"pending request", "changed signature after tar retirement"} {
		t.Run(condition, func(t *testing.T) {
			u, key := seedInstalledImages(t)
			raw := testImage(t, "runner", u.Arch, "v1")
			putInboxImage(t, u, "runner", "v1", raw, signImageFixture(t, key, raw))
			img, err := u.StageImage(t.Context(), "runner", "v1")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(u.Data, "images", imageFilename(img.Ref()))
			if condition == "pending request" {
				if os.WriteFile(filepath.Join(u.Data, "state", imageRequestFile), []byte("unresolved"), 0600) != nil {
					t.Fatal("pending fixture")
				}
				_ = PruneImages(t.Context(), u.Data, u.Arch, nil)
				if VerifyImageRef(t.Context(), u.Data, img.Ref(), u.Arch) != nil {
					t.Fatal("stale keep set retired a pending archive")
				}
			} else {
				if os.Remove(path) != nil || os.WriteFile(path+".sig", []byte("owner replacement"), 0600) != nil {
					t.Fatal("interrupted-retirement fixture")
				}
				if err := PruneImages(t.Context(), u.Data, u.Arch, nil); err != nil {
					t.Fatal(err)
				}
				if b, e := os.ReadFile(path + ".sig"); e != nil || string(b) != "owner replacement" {
					t.Fatal("changed signature removed by stale inode alone")
				}
			}
		})
	}
}

// Real installs have two signed archives, an owner ID, and a receipt for
// each component, even before the first successful update.
func seedInstalledImages(t *testing.T) (*CoreUpdater, *ecdsa.PrivateKey) {
	t.Helper()
	u, key := seedImageTrust(t)
	boot, err := ReadImageBootstrap(u.Data)
	if err != nil {
		t.Fatal("cannot seed publisher trust")
	}
	state := filepath.Join(u.Data, "state")
	id := strings.Repeat("a", 32)
	if os.WriteFile(filepath.Join(state, "install.id"), []byte(id), 0600) != nil {
		t.Fatal("cannot seed installation ID")
	}
	for _, comp := range []string{"tikray", "runner"} {
		ref := stageRetainedImage(t, u, key, comp, "original")
		if comp == "tikray" {
			boot.Tikray = ref
		} else {
			boot.Runner = ref
		}
		record := map[string]any{"version": 1, "installation_id": id, "active": ref, "previous": nil}
		b, _ := json.Marshal(record)
		if os.WriteFile(filepath.Join(state, "image-"+comp+".receipt"), b, 0600) != nil {
			t.Fatal("cannot seed original receipt")
		}
	}
	b, _ := json.Marshal(boot)
	if os.WriteFile(filepath.Join(state, imageBootstrapFile), b, 0600) != nil {
		t.Fatal("cannot seed original references")
	}
	return u, key
}

func stageRetainedImage(t *testing.T, u *CoreUpdater, key *ecdsa.PrivateKey, component, tag string) ImageRef {
	t.Helper()
	raw := imageWithStateLabel(t, component, u.Arch, tag, "2")
	putInboxImage(t, u, component, tag, raw, signImageFixture(t, key, raw))
	v, e := u.StageImage(t.Context(), component, tag)
	if e != nil {
		t.Fatal("cannot stage signed slot")
	}
	return v.Ref()
}

func TestImageCollectionRequiresVerifiedRetainedArchives(t *testing.T) {
	for _, fault := range []string{"incorrect prior digest", "invalid active signature", "invalid prior chain", "missing bootstrap", "missing sibling receipt", "correct"} {
		t.Run(fault, func(t *testing.T) {
			u, key := seedInstalledImages(t)
			st := filepath.Join(u.Data, "state")
			dir := filepath.Join(u.Data, "images")
			control := stageRetainedImage(t, u, key, "tikray", "control-update")
			boot, err := ReadImageBootstrap(u.Data)
			if err != nil {
				t.Fatal("cannot read seeded originals")
			}
			prior := stageRetainedImage(t, u, key, "runner", "prior")
			running := stageRetainedImage(t, u, key, "runner", "current")
			leftover := stageRetainedImage(t, u, key, "runner", "unused")
			id := strings.Repeat("a", 32)
			save := func(component string, active, old ImageRef) {
				t.Helper()
				b, _ := json.Marshal(imageReceipt{1, id, active, old})
				if os.WriteFile(filepath.Join(st, "image-"+component+".receipt"), b, 0600) != nil {
					t.Fatal("cannot write seeded lineage")
				}
			}
			save("tikray", control, boot.Tikray)
			claimed := prior
			switch fault {
			case "incorrect prior digest":
				claimed.Digest = alterImageHex(prior.Digest)
			case "invalid prior chain":
				claimed.Chain = alterImageHex(prior.Chain)
			case "invalid active signature":
				if os.WriteFile(filepath.Join(dir, imageFilename(running)+".sig"), []byte("changed"), 0600) != nil {
					t.Fatal("cannot change signature")
				}
			case "missing sibling receipt":
				if os.Remove(filepath.Join(st, "image-tikray.receipt")) != nil {
					t.Fatal("cannot remove sibling receipt")
				}
			case "missing bootstrap":
				if os.Remove(filepath.Join(dir, imageFilename(boot.Runner))) != nil {
					t.Fatal("cannot remove original image")
				}
			}
			save("runner", running, claimed)
			// Refusal cleanup has its own path, which must also preserve a
			// genuine previous release if the damaged receipt no longer names it.
			if _, err = u.BeginImageUpdate(t.Context(), VerifiedImage{prior}); err == nil {
				t.Fatal("simulated refusal missing")
			}
			if VerifyImageRef(t.Context(), u.Data, prior, u.Arch) != nil {
				t.Error("early cleanup destroyed the real previous release")
			}
			if fault != "correct" {
				if _, _, e := RetainedStateSchemas(t.Context(), u.Data); e == nil {
					t.Error("unverified retained material authorized state pruning")
				}
			}
			e := PruneInstalledImages(t.Context(), u.Data)
			if fault != "correct" && e == nil {
				t.Error("uncertain lineage allowed collection")
			}
			if fault == "correct" {
				if e != nil {
					t.Fatal("healthy lineage refused collection")
				}
				for _, ref := range []ImageRef{boot.Tikray, boot.Runner, control, running, prior} {
					if VerifyImageRef(t.Context(), u.Data, ref, u.Arch) != nil {
						t.Error("healthy collection lost a retained signed archive")
					}
				}
			}
			for _, ext := range []string{"", ".sig", ".owned"} {
				if _, e = os.Stat(filepath.Join(dir, imageFilename(prior)+ext)); e != nil {
					t.Error("retirement destroyed known rollback material")
				}
				_, e = os.Stat(filepath.Join(dir, imageFilename(leftover)+ext))
				if fault == "correct" && !os.IsNotExist(e) {
					t.Error("healthy collection did not reclaim orphan")
				}
				if fault != "correct" && e != nil {
					t.Error("uncertain collection deleted an archive")
				}
			}
		})
	}
}

func alterImageHex(value string) string {
	first := "0"
	if value[0] == '0' {
		first = "1"
	}
	return first + value[1:]
}
