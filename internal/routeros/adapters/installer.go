package adapters

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strings"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

func archiveVerifier(images []VerifiedArchive) string {
	var b strings.Builder
	// Keep each literal well under the RouterOS string limit. The router
	// holds one file chunk and one small group of expected hashes at a time.
	b.WriteString(`    :local verifyStaged do={
    :local component $1
    :local path $2
    :local verifyChunk do={
        :local data ([/file/read file=$1 offset=$2 chunk-size=$3 as-value]->"data")
        :if (([:len $data] != $3) or ([:convert [:convert $data from=raw transform=sha512 to=hex] transform=lc] != $4)) do={ :error "tikray: image digest mismatch; replace archive" }
        :return true
    }
`)
	for _, a := range images {
		fmt.Fprintf(&b, "    :if ($component = \"%s\") do={\n", a.component)
		fmt.Fprintf(&b, "        :local fileIDs [/file/find where name=$path]\n        :if ([:len $fileIDs] != 1) do={ :error \"tikray: upload the signed %s archive\" }\n", a.component)
		fmt.Fprintf(&b, "        :local fileID [:pick $fileIDs 0]\n        :if ([/file/get $fileID size] != %d) do={ :error \"tikray: image length mismatch; replace archive\" }\n        :local offset 0\n", a.size)
		for i := 0; i < len(a.digests); i += 16 {
			b.WriteString("        :foreach expected in={")
			for j, d := range a.digests[i:min(i+16, len(a.digests))] {
				if j > 0 {
					b.WriteByte(';')
				}
				fmt.Fprintf(&b, "\"%x\"", d)
			}
			fmt.Fprintf(&b, `} do={
            :local n %d
            :if (($offset + $n) > %d) do={ :set n (%d - $offset) }
            :if ([$verifyChunk $path $offset $n $expected] != true) do={ :error "tikray: verify image chunk" }
            :set offset ($offset + $n)
        }
`, installerChunkSize, a.size, a.size)
		}
		fmt.Fprintf(&b, `        :local endIDs [/file/find where name=$path]
        :if (([:len $endIDs] != 1) or ([:pick $endIDs 0] != $fileID) or ($offset != %d)) do={ :error "tikray: staged archive changed during verification" }
        :if ([/file/get $fileID size] != $offset) do={ :error "tikray: staged archive length changed" }
        :return true
    }
`, a.size)
	}
	b.WriteString(`    :error "tikray: unknown image component"
    }`)
	return b.String()
}

func archiveChecks(images []VerifiedArchive) string {
	var b strings.Builder
	for _, a := range images {
		file := a.component + "-" + a.arch + ".tar"
		fmt.Fprintf(&b, "    { :local path ($base . \"/images/%s\")\n", file)
		if a.releaseBase != "" {
			fmt.Fprintf(&b, `        :if ((!$offline) and ([:len [/file/find where name=$path]] = 0)) do={
            $requireInstall $lease
            :local nonce ($lease->"nonce")
            :if (([:len $nonce] != 32) or (!($nonce ~ "^[0-9a-f]+\$"))) do={ :error "tikray: missing download lease" }
            :local incoming ($base . "/images/incoming-" . $nonce . "-%s")
            :if ([:len [/file/find where name=$incoming]] != 0) do={ :error "tikray: download staging conflict" }
            /file/add name=$incoming type=file
            :local transferID [:pick [/file/find where name=$incoming] 0]
            :do {
                # The public release origin must return the archive directly. A
                # redirect can carry a signed URL in its response headers.
                :local result [/tool/fetch url="%s/%s" check-certificate=yes http-max-redirect-count=0 dst-path=$incoming as-value]
                :if (($result->"status") != "finished") do={ :error "tikray: incomplete HTTPS download" }
                :if ([$verifyStaged "%s" $incoming] != true) do={ :error "tikray: download digest differs" }
                $requireInstall $lease
                :if (([:len [/file/find where .id=$transferID and name=$incoming]] != 1) or ([:len [/file/find where name=$path]] != 0)) do={ :error "tikray: download staging changed" }
                /file/set $transferID name=$path
            } on-error={
                :if ([:len [/file/find where .id=$transferID and name=$incoming]] = 1) do={ /file/remove $transferID }
                :error "tikray: image download failed; verify the HTTPS source or upload the signed archive"
            }
        }
`, file, a.releaseBase, file, a.component)
		}
		fmt.Fprintf(&b, "        :if ([$verifyStaged \"%s\" $path] != true) do={ :error \"tikray: verify both image archives\" }\n    }\n", a.component)
	}
	b.WriteString("    :set archivesVerified true")
	return b.String()
}

// A RouterOS script source is stored as literal text. Interpolate variables
// only when the scheduler executes it. Split the expression into lines so
// no physical import line has to hold the entire watchdog.
func scriptLiteral(source string) string {
	escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`)
	lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	for i, line := range lines {
		lines[i] = `"` + escape.Replace(line) + `\r\n"`
	}
	return "(" + strings.Join(lines, " . \\\n        ") + ")"
}

// Use the same reviewed emergency body for development imports and for a
// packaged install. Supplying explicit source text in a release gives
// repeat imports a stable identity even if console pretty-printing differs.
func emergencySource(script string) (body, install string, err error) {
	const start = "policy=read,write,test source={"
	const end = "\n        }\n    }\n}"
	left, rest, ok := strings.Cut(script, start)
	content, right, okEnd := strings.Cut(rest, end)
	if !ok || !okEnd || strings.TrimSpace(right) != "" {
		return "", "", errors.New("installer: invalid emergency script source")
	}
	body = content + "\n        "
	return body, left + "policy=read,write,test source=$offBody\n    }\n}" + right, nil
}

// BuildInstaller emits a single offline-importable RouterOS program.
func BuildInstaller(p Profile, images []VerifiedArchive, dst io.Writer) error {
	return buildInstaller(p, images, dst, routerosfiles.Sources.ReadFile)
}

// A source failure must leave the destination untouched, including when
// it occurs after both archive manifests have been accepted.
func buildInstaller(p Profile, images []VerifiedArchive, dst io.Writer, readSource func(string) ([]byte, error)) error {
	if p.Version() == "" || len(images) != 2 || images[0].component != "tikray" || images[1].component != "tikray-runner" {
		return errArchive
	}
	total := 0
	for _, a := range images {
		if a.arch != p.GOARCH() || a.size < 1 || a.size > maxArchive || len(a.digests) != (a.size+installerChunkSize-1)/installerChunkSize || a.releaseBase != images[0].releaseBase {
			return errArchive
		}
		total += a.size
	}
	body, e := readSource("install.rsc")
	if e != nil {
		return errors.New("installer: missing source")
	}
	source := string(body)
	replace := func(key, value string) error {
		if strings.Count(source, key) != 1 {
			return errors.New("installer: invalid template")
		}
		source = strings.Replace(source, key, value, 1)
		return nil
	}
	for _, f := range []struct{ slot, file string }{{"CERTIFICATE", "certificate.rsc"}, {"LOCK", "install-lock.rsc"}, {"EMERGENCY", "emergency-off.rsc"}, {"BINDINGS", "bindings.rsc"}} {
		data, err := readSource(f.file)
		if err != nil {
			return errors.New("installer: missing script fragment")
		}
		fragment := string(data)
		if f.slot == "EMERGENCY" {
			body, install, err := emergencySource(fragment)
			if err != nil {
				return err
			}
			fragment = install
			proof := fmt.Sprintf(`:local offBody %s
    :if ([:len $emergency] = 1) do={
        :local saved [/system/script/get $emergency source]
        :local sum [:convert [:convert $saved from=raw transform=sha512 to=hex] transform=lc]
        :if (($saved != $offBody) and ($saved != ($offBody . "\r\n")) and ($saved != ($offBody . "\n")) and ($sum != "%x") and ($sum != "%x") and ($sum != "%x") and ($sum != "%x")) do={ :error "tikray: inspect changed emergency script before installing" }
    }`, scriptLiteral(body), sha512.Sum512([]byte(body)), sha512.Sum512([]byte(strings.ReplaceAll(body, "\n", "\r\n"))),
				sha512.Sum512([]byte(body+"\n")), sha512.Sum512([]byte(strings.ReplaceAll(body+"\n", "\n", "\r\n"))))
			if err = replace("# @TIKRAY_EMERGENCY_PROOF@", proof); err != nil {
				return err
			}
		}
		if err = replace("# @TIKRAY_"+f.slot+"@", fragment); err != nil {
			return err
		}
	}
	watch, e := readSource("watchdog.rsc")
	if e != nil {
		return errors.New("installer: missing watchdog")
	}
	watchBody := string(watch)
	var stateSource string
	for _, part := range []struct{ slot, file string }{{"STEP", "watchdog-step.rsc"}, {"STATE", "watchdog-state.rsc"}, {"BINDINGS", "bindings.rsc"}, {"HEALTH", "watchdog-health.rsc"}} {
		b, err := readSource(part.file)
		if err != nil {
			return errors.New("installer: missing watchdog logic")
		}
		key := "# @TIKRAY_WATCHDOG_" + part.slot + "@"
		if strings.Count(watchBody, key) != 1 {
			return errors.New("installer: invalid watchdog template")
		}
		watchBody = strings.Replace(watchBody, key, string(b), 1)
		if part.slot == "STATE" {
			stateSource = string(b)
		}
	}
	pre, e := readSource("watchdog-preflight.rsc")
	if e != nil {
		return errors.New("installer: missing watchdog preflight")
	}
	if e = replace("# @TIKRAY_WATCHDOG_PREFLIGHT@", ":local watchBody "+scriptLiteral(watchBody)+"\n"+stateSource+"\n    :local watchStateCheck [$wdState \"inspect\"]\n"+string(pre)); e != nil {
		return e
	}
	if e = replace("# @TIKRAY_WATCHDOG@", `:local watchStateInit [$wdState "init" [$readWatchID $data]]
    :if ([$provisionWatch true $watchBody] != true) do={ :error "tikray: watchdog provisioning failed" }`); e != nil {
		return e
	}
	platform := fmt.Sprintf(`:if (($arch != "%s") or ([:pick [/system/resource/get version] 0 [:find ([/system/resource/get version] . " ") " "]] != "%s")) do={ :error "tikray: obtain installer matching installed architecture and version" }; :set imageBytes %d`, p.GOARCH(), p.Version(), total)
	if e = replace("# @TIKRAY_PLATFORM@", platform); e != nil {
		return e
	}
	if e = replace("# @TIKRAY_VERIFIER@", archiveVerifier(images)); e != nil {
		return e
	}
	if e = replace("# @TIKRAY_ARCHIVES@", archiveChecks(images)); e != nil {
		return e
	}
	if strings.Contains(source, "# @TIKRAY_") {
		return errors.New("installer: unexpanded template")
	}
	_, e = io.WriteString(dst, source)
	return e
}
