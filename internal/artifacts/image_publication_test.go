package artifacts

import (
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
			u, key := seedImageTrust(t)
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
			u, key := seedImageTrust(t)
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
			if os.WriteFile(filepath.Join(state, "install.id"), []byte(id), 0600) != nil || os.WriteFile(filepath.Join(state, "image-runner.json"), receipt, 0600) != nil {
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
			u, key := seedImageTrust(t)
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
