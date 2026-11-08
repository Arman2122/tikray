# The binding check precedes this probe. An ID distinguishes services; it
# is public and the request carries no credentials. Bound the whole fetch
# so a slow response cannot keep subsequent watchdog ticks from running.
:do {
    :local response [/tool/fetch url=("https://" . $ctlIP . "/healthz") src-address=$gateway check-certificate=no http-max-redirect-count=0 idle-timeout=3s duration=5s output=user as-value]
    :local payload ($response->"data")
    :if ((($response->"status") = "finished") and ([:len $payload] > 0) and ([:len $payload] <= 160)) do={
        :local body [:deserialize from=json options=json.no-string-conversion value=$payload]
        :set healthy (([:typeof ($body->"ok")] = "bool") and (($body->"ok") = true) and ([:typeof ($body->"installation_id")] = "str") and (($body->"installation_id") = ($savedState->"installation_id")))
    }
} on-error={ :set healthy false }
