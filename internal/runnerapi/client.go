package runnerapi

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// maxBody bounds what the client reads from the runner; xray api output
	// is the largest thing it sends.
	maxBody = 8 << 20
	// maxErrText bounds the response body quoted in an error message.
	maxErrText = 1024
)

var (
	defaultHTTP = &http.Client{Timeout: 10 * time.Second}
	// testHTTP is Test's default: the runner gives xray run -test 20 s.
	testHTTP = &http.Client{Timeout: 30 * time.Second}
)

// Client calls the runner's control API.
type Client struct {
	BaseURL string // such as http://192.168.88.2:8080
	Token   string
	// TokenFunc, if set, makes the token of each request, and Token is not
	// used. A call whose token can't be had (it returns an error) fails with
	// that error before anything is sent. It lets a client wait for a runner
	// that has not made its token yet, for which it returns ErrNoToken. It is
	// called from whatever goroutine calls the client, and a copy of the
	// client keeps it.
	TokenFunc func(ctx context.Context) (string, error)
	// Unauthorized, if set, is called with the token of each request that the
	// runner answers 401: it is not the runner's token, as when the runner
	// has made a new one since TokenFunc read it. A TokenFunc that keeps its
	// token can drop it then, to read it again for the next call. It is
	// called as TokenFunc is.
	Unauthorized func(token string)
	HTTP         *http.Client // nil means a client with a 10 s timeout
}

// errBody is the runner's JSON error body.
type errBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// Status returns the runner's state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &st)
	if err != nil {
		return Status{}, err
	}
	if st.LastTrial != nil && st.LastTrial.Outcome == OutcomeRejected {
		st.LastTrial.Detail = publicRefusal(st.LastTrial.Detail)
	}
	return st, err
}

// Trial starts a trial of the candidate in candidate.json. It returns a
// *TestFailedError when xray run -test rejects the config, and ErrBusy when a
// trial is already open.
func (c *Client) Trial(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/trial", nil, nil)
}

// Commit makes the open trial's candidate the active selection. It returns
// ErrNoTrial when no trial is open.
func (c *Client) Commit(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/commit", nil, nil)
}

// Abort ends the open trial and reverts to the active selection. It returns
// ErrNoTrial when no trial is open.
func (c *Client) Abort(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/abort", nil, nil)
}

// Restart restarts xray from the active selection.
func (c *Client) Restart(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/restart", nil, nil)
}

// Reload asks the runner to re-read active.json and start it.
func (c *Client) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/reload", nil, nil)
}

// Adopt makes config, a file under the runner's run directory named like
// Selection.Config, the active one without restarting xray: the running xray
// must already run it, as after a change made through XrayAPI. The core and
// geo stay those of the running xray. It returns ErrBusy during a trial or a
// restart and ErrNoCore when no xray runs; a name that is invalid, or a file
// that does not exist, is a 400 error.
func (c *Client) Adopt(ctx context.Context, config string) error {
	return c.do(ctx, http.MethodPost, "/v1/adopt", AdoptRequest{Config: config}, nil)
}

// XrayAPI runs "xray api <args>" in the runner and returns its output.
func (c *Client) XrayAPI(ctx context.Context, args ...string) (XrayAPIResponse, error) {
	if args == nil {
		args = []string{}
	}
	var resp XrayAPIResponse
	err := c.do(ctx, http.MethodPost, "/v1/xray-api", XrayAPIRequest{Args: args}, &resp)
	if err != nil {
		return XrayAPIResponse{}, err
	}
	if len(args) > 0 {
		resp = PublicXrayResult(args[0], resp)
	}
	return resp, err
}

// Test has the runner run "xray run -test" on config, an xray config in JSON,
// with the core that runs now. A config xray rejects is a TestResult with OK
// false, not an error. It returns ErrNoCore when no xray runs. The runner
// takes up to 20 s; with HTTP nil the client waits 30 s, and an HTTP of its
// own must allow as much.
func (c *Client) Test(ctx context.Context, config []byte) (TestResult, error) {
	var res TestResult
	err := c.send(ctx, testHTTP, http.MethodPost, "/v1/test", config, &res)
	if err != nil {
		return TestResult{}, err
	}
	if !res.OK && legacyTestTimeout(res.Output) {
		return TestResult{}, fmt.Errorf("runnerapi: xray run -test: %w", context.DeadlineExceeded)
	}
	if res.OK {
		return ConfigVerdict(0), nil
	}
	res.Output = publicRefusal(res.Output)
	return res, nil
}

// publicRefusal is the public form of a runner's reason for a refusal. A
// runner's own reasons, from ConfigRefusal, are fixed words and public tags
// and stay as they are. Older runners returned raw child output, sometimes
// containing escaped or transformed credentials: project it onto the same
// tags and fixed categories (see classifyRefusal) before it can enter an
// error, a persisted verdict or history.
func publicRefusal(text string) string {
	if text == "" {
		return ""
	}
	if publicRefusalRE.MatchString(text) {
		return text
	}
	const prefix = "xray failed to load config (exit "
	if n, ok := strings.CutPrefix(text, prefix); ok {
		if n, ok := strings.CutSuffix(n, ")"); ok {
			if code, err := strconv.Atoi(n); err == nil && code > 0 && code <= 255 {
				return ConfigVerdict(code).Output
			}
		}
	}
	switch {
	case strings.Contains(text, TestOutputTruncated):
		return TestOutputTruncated
	case strings.Contains(text, "xray run -test did not finish within"):
		return "xray config test did not finish"
	}
	tags, category := classifyRefusal(text)
	return refusalText(tags, cmp.Or(category, refusalLegacy))
}

// The previous runner sent its own timeout as a rejection, with this line
// before any xray output. Only a completed test can condemn a server.
func legacyTestTimeout(output string) bool {
	line, _, ended := strings.Cut(output, "\n")
	duration, ok := strings.CutPrefix(line, "xray run -test did not finish within ")
	if !ended || !ok {
		return false
	}
	d, err := time.ParseDuration(duration)
	return err == nil && d > 0 && d.String() == duration
}

// do sends one request, see send.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	return c.send(ctx, defaultHTTP, method, path, in, out)
}

// send sends one request with c.HTTP, or with def when that is nil. in is
// encoded as JSON, except that a []byte is sent as it is. A 2xx answer is
// decoded into out when out is non-nil; anything else becomes an error, see
// statusError.
func (c *Client) send(ctx context.Context, def *http.Client, method, path string, in, out any) error {
	var body io.Reader
	switch in := in.(type) {
	case nil:
	case []byte:
		body = bytes.NewReader(in)
	default:
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("runnerapi: %s %s: %w", method, path, err)
		}
		body = bytes.NewReader(b)
	}
	token := c.Token
	if c.TokenFunc != nil {
		var err error
		if token, err = c.TokenFunc(ctx); err != nil {
			return fmt.Errorf("runnerapi: %s %s: %w", method, path, err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return fmt.Errorf("runnerapi: %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = def
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("runnerapi: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("runnerapi: %s %s: reading response: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == http.StatusUnauthorized && c.Unauthorized != nil {
			c.Unauthorized(token)
		}
		if len(raw) > maxBody {
			// Parsing a cut JSON response can leave a credential fragment.
			raw = nil
		}
		return statusError(method, path, resp, raw)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("runnerapi: %s %s: response exceeds limit", method, path)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("runnerapi: %s %s: decoding response: %w", method, path, err)
	}
	return nil
}

// statusError turns a non-2xx answer into the error the caller can test for.
func statusError(method, path string, resp *http.Response, raw []byte) error {
	var eb errBody
	_ = json.Unmarshal(raw, &eb) // a body that is not JSON leaves eb empty
	// Older runners sometimes put process diagnostics in error bodies.
	// Only the config refusal code, a busy/no-core sentinel, or the fixed
	// words of a test that ended without a verdict is meaningful.
	command := path == "/v1/test" || path == "/v1/trial" || path == "/v1/xray-api"
	fault := path != "/v1/xray-api" && resp.StatusCode == http.StatusInternalServerError && PublicTestError(eb.Detail)
	if command && resp.StatusCode != http.StatusUnprocessableEntity && !fault {
		eb.Detail = ""
	}
	switch {
	case resp.StatusCode == http.StatusConflict && eb.Error == "busy":
		return wrapDetail(ErrBusy, eb.Detail)
	case resp.StatusCode == http.StatusConflict && eb.Error == "no_trial":
		return wrapDetail(ErrNoTrial, eb.Detail)
	case resp.StatusCode == http.StatusConflict && eb.Error == "no_core":
		return wrapDetail(ErrNoCore, eb.Detail)
	case resp.StatusCode == http.StatusUnprocessableEntity:
		out := eb.Detail
		if out == "" {
			out = strings.TrimSpace(string(raw))
		}
		return &TestFailedError{Output: publicRefusal(out)}
	}
	if fault {
		return fmt.Errorf("runnerapi: %s %s: HTTP %d: %s", method, path, resp.StatusCode, eb.Detail)
	}
	if command {
		return fmt.Errorf("runnerapi: %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	text := strings.TrimSpace(string(raw))
	if len(text) > maxErrText {
		text = "" // a prefix can contain part of a credential
	}
	if text == "" {
		return fmt.Errorf("runnerapi: %s %s: %s", method, path, resp.Status)
	}
	return fmt.Errorf("runnerapi: %s %s: %s: %s", method, path, resp.Status, text)
}

// wrapDetail keeps the sentinel testable with errors.Is and adds the runner's
// explanation when it gave one.
func wrapDetail(err error, detail string) error {
	if detail == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, detail)
}
