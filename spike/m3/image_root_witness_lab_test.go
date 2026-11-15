//go:build lab

package m3

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	routerfiles "github.com/Arman2122/tikray/routeros"
)

// A container store hides its children in /file/find. The restricted
// scheduler must still recognize the entire nonce value and leave a differing
// file in place, including one whose contents start with the expected tag.
func TestNativeImageRootWitness(t *testing.T) {
	f := newNativeImageCase(t)
	root := strings.TrimSuffix(f.data, "/data") + "/containers/control"
	tag := "tikray:image-import:" + nativeImageNonce + ":new"
	f.req(nativeImageNonce, f.first, f.second)
	if e := f.tick(); e != "" || !f.isLive(f.second) {
		t.Fatal("could not stage real extracted image", e)
	}
	actual := root + "/tikray-import-" + nativeImageNonce + ".receipt"
	read := func(path string, want string) bool {
		t.Helper()
		return f.run(`{:local ok false; :do {:local v ([/file/read file="`+path+`" offset=0 chunk-size=200 as-value]->"data"); :set ok (([:len $v]=`+strconv.Itoa(len(want))+`) and ($v="`+want+`"))} on-error={};:put $ok}`) == "true"
	}
	if !read(actual, tag) {
		t.Fatal("actual imported root lacks its readable complete ownership witness")
	}
	source, e := routerfiles.Sources.ReadFile("watchdog-image.rsc")
	if e != nil {
		t.Fatal("native image machine unavailable")
	}
	const begin = "    :local imageRootWitness do={"
	start := strings.Index(string(source), begin)
	if start < 0 {
		t.Fatal("native root witness implementation missing")
	}
	off := strings.Index(string(source)[start:], "\n    }\n")
	if off < 0 {
		t.Fatal("native root witness incomplete")
	}
	helper := string(source)[start : start+off+len("\n    }")]
	changed := root + "/tikray-import-witness-foreign.receipt"
	fresh := root + "/tikray-import-witness-fresh.receipt"
	f.run(`/file/add name="` + changed + `" type=file contents="` + tag + `x"`)
	if !read(changed, tag+"x") {
		t.Fatal("existing owner content witness unavailable")
	}
	f.run(`/system/script/add name=m3-witness-status source="" policy=read comment="waiting"`)
	code := "{" + helper + "\n" +
		`:local existing [$imageRootWitness "read" "` + actual + `" "` + tag + `"]; :local refused (![$imageRootWitness "create" "` + changed + `" "` + tag + `"]); :local create [$imageRootWitness "create" "` + fresh + `" "` + tag + `"]; :local again [$imageRootWitness "create" "` + fresh + `" "` + tag + `"]; :local check [$imageRootWitness "read" "` + fresh + `" "` + tag + `"]; /system/script/set [find name=m3-witness-status] comment=([:tostr $existing] . "|" . $refused . "|" . $create . "|" . $again . "|" . $check)}`
	if _, e := f.r.admin.RunContext(f.r.ctx, "/system/script/add", "=name=m3-witness-probe", "=policy=read,write,test,ftp", "=source="+code); e != nil {
		t.Fatal("could not store root witness probe")
	}
	f.run(`/system/scheduler/add name=m3-witness-scheduler policy=read,write,test,ftp on-event=m3-witness-probe interval=3s start-time=startup`)
	if e := ownerWait(f.r.ctx, 35*time.Second, func(c context.Context) (bool, error) {
		b, e := f.r.chr.RunPrivate(c, `:put [/system/script/get [find name=m3-witness-status] comment]`)
		return strings.TrimSpace(b) == "true|true|true|true|true", e
	}); e != nil {
		t.Fatal("scheduled read, creation, repeat or foreign-file refusal failed")
	}
	if !read(changed, tag+"x") || !read(fresh, tag) {
		t.Fatal("native witness did not preserve exact foreign bytes or its own creation")
	}
}

// A failed native extraction can leave its nonce-bound row without a Docker
// ID. An owner may subsequently populate the same path. A correct-looking
// marker with trailing bytes cannot authorize deleting that directory.
func TestNativeImageRestorePreservesRecreatedRoot(t *testing.T) {
	f := newNativeImageCase(t)
	raw, id := nativeProbeArchive(t, "interrupted-layer")
	var damaged bytes.Buffer
	save := tar.NewWriter(&damaged)
	read := tar.NewReader(bytes.NewReader(raw))
	for {
		h, e := read.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal("cannot read source test image")
		}
		part, e := io.ReadAll(read)
		if e != nil {
			t.Fatal("cannot read test image entry")
		}
		if strings.HasSuffix(h.Name, "/layer.tar") {
			part = part[:len(part)/2+17]
		}
		h.Size = int64(len(part))
		if save.WriteHeader(h) != nil {
			t.Fatal("cannot stage damaged image header")
		}
		if _, e = save.Write(part); e != nil {
			t.Fatal("cannot stage damaged image body")
		}
	}
	if save.Close() != nil {
		t.Fatal("cannot close damaged fixture")
	}
	bad := f.buildArchive(damaged.Bytes(), id)
	f.req(nativeImageNonce, f.first, bad)
	// Let RouterOS actually reject the incomplete layer and publish the journal.
	_ = f.tick()
	tag := "tikray:image-import:" + nativeImageNonce + ":new"
	row := f.run(`{:local r [/container/find where name=tikray and comment="` + tag + `"];:if ([:len $r]=1) do={:local q [:pick $r 0];:if ([:len [:tostr [/container/get $q image-id]]]=0) do={:put [:tostr $q]}}}`)
	if !regexp.MustCompile(`^\*[0-9a-fA-F]+$`).MatchString(row) {
		t.Fatal("failed import did not leave the required native provisional row")
	}
	root := strings.TrimSuffix(f.data, "/data") + "/containers/control"
	if f.run(`:put [:len [/file/find where name="`+root+`"]]`) != "0" {
		// Preserve the disposable original outside the live path. The foreign
		// directory below must be independently owned even if the importer left one.
		f.run(`/file/set [find where name="` + root + `"] name="` + root + `-saved-fixture"`)
	}
	mark := root + "/tikray-import-" + nativeImageNonce + ".receipt"
	witness := root + "/unrelated-proof.txt"
	f.run(`/file/add type=directory name="` + root + `"; /file/add type=file name="` + witness + `" contents="independent-owner"; /file/add type=file name="` + mark + `" contents="` + tag + `x"`)
	f.run(`{:local id [/system/script/find where name=tikray-image-transition];:local prefix "tikray:image-transition ";:local j [:deserialize from=json options=json.no-string-conversion value=[:pick [/system/script/get $id comment] [:len $prefix] 4096]];:set ($j->"age") 300;/system/script/set $id comment=($prefix . [:serialize to=json options=json.no-string-conversion value=$j])}`)
	f.run(`/system/script/add name=m3-root-restore-result source="" policy=read comment="waiting"`)
	body := f.run(`:put [/file/get m3-watch-images.rsc contents]`)
	program := "{:local verdict \"unexpected\"; :onerror why in={" + body + `} do={:if ([:typeof [:find [:tostr $why] "image: incomplete root ownership unknown"]]="num") do={:set verdict "protected"}}; /system/script/set [find name=m3-root-restore-result] comment=$verdict}`
	if _, e := f.r.admin.RunContext(f.r.ctx, "/system/script/add", "=name=m3-root-restore", "=policy=read,write,test,ftp", "=source="+program); e != nil {
		t.Fatal("cannot publish native restore assertion")
	}
	f.run(`/system/scheduler/add name=m3-reject-root policy=read,write,test,ftp on-event=m3-root-restore interval=20s start-time=startup`)
	if e := ownerWait(f.r.ctx, 60*time.Second, func(c context.Context) (bool, error) {
		b, e := f.r.chr.RunPrivate(c, `:put [/system/script/get [find name=m3-root-restore-result] comment]`)
		return strings.TrimSpace(b) == "protected", e
	}); e != nil {
		t.Fatal("native restore did not refuse the ambiguous extraction root")
	}
	if f.run(`:put [:tostr [/container/find where name=tikray and comment="`+tag+`"]]`) != row ||
		f.run(`:put (([/file/read file="`+witness+`" offset=0 chunk-size=64 as-value]->"data")="independent-owner")`) != "true" ||
		f.run(`:put (([/file/read file="`+mark+`" offset=0 chunk-size=96 as-value]->"data")="`+tag+`x")`) != "true" {
		t.Fatal("refused restore disturbed the unrelated root or provisional row")
	}
}
