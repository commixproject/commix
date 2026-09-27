# How commix is put together

Written for somebody about to change something and wanting to know what they are standing on. It
follows a payload: where it is built, what it is wrapped in, how it leaves, what is made of the
answer, and what survives to the next target. The source settles anything this disagrees with.

## A payload's journey

A run is one loop around a target, and a target is one loop around its parameters.

`commix.py` checks the interpreter and hands over to `src/core/main.py`. `run()` settles what can be
settled before there is a target at all - `src/core/startup.py: bootstrap()` - and then finds the
targets: a URL, a request file, a proxy log, a bulk file, a crawl, a sitemap, standard input.

For each of them `main()` connects once and reads that answer for everything it can tell: the
character encoding, the web server, the technology behind it, the operating system. The page itself
is kept (`requests.capture_original_page()`), because what a parameter is later compared against,
what the forms are parsed out of and what the proof is written from all want the same page, and none
of them is worth a second request.

Then `controller.do_check()`, and from there the shape is:

    perform_checks()        which places are tested, and in what order
      injection_process()   one parameter: heuristics, then technique after technique
        do_injection()      a finding - report it, store it, go on to exploitation

`perform_checks()` walks the URL, the POST body, the cookies, the standard headers and any custom
header. How far down that list it gets is what `--level` decides.

## What is being injected into

Two different things, and the distinction runs through the whole tree.

**A shell.** The value is handed to a command. A payload is a command chained onto the original with
a separator, and what makes it work is the shell's syntax.

**An evaluator.** The value is evaluated as code in the application's own language (`--eval`). A
shell separator means nothing here - a semicolon is a semicolon in a PHP statement, not a chain. The
payload has to be valid code in the language doing the evaluating.

The techniques are the same for both, so the two sinks are two sets of payload builders behind one
set of handlers:

|  | shell | evaluator |
|--|-------|-----------|
| payloads | `src/core/techniques/<technique>/*_payloads.py` | `src/core/eval/payloads/<technique>.py` |
| where the syntax comes from | the target's shell | `src/core/eval/grammars/php.py`, `python.py` |

A grammar carries its own probe, the functions that run a command, the boundaries that break into an
evaluated string and close it again, and the print statement results come back through. Teaching
commix another language is a new module in `grammars/` and nothing else.

## The techniques

Each one is three modules with the same shape, and reading them in this order is the fastest way to
understand any of them:

    *_payloads.py   what gets sent
    *_injector.py   sending it and reading the answer
    *_handler.py    running the technique, and pulling output through it once it works

| Technique | Package | Asked for with | Where the answer is read |
|-----------|---------|----------------|--------------------------|
| results-based | `techniques/classic/` | `--technique=r` | the page |
| dynamic code evaluation | `eval/` | `--eval=<language>` | the page |
| time-based | `techniques/time_based/` | `--technique=t` | how long the answer took |
| file-based | `techniques/file_based/` | `--technique=f` | a file under the web root |
| tempfile-based | `techniques/tempfile_based/` | under `f`, where the web root cannot be written | a file in a temporary directory |
| out-of-band | `techniques/oob/` | `--oob` | a request the target makes to a server you control |

`AVAILABLE_TECHNIQUES` is `r`, `t`, `f` and nothing else. Out-of-band is kept out of it on purpose:
it is a switch, so that the modules can use it too, and those never go through `--technique`. The
evaluator composes with the three letters rather than replacing them - `EVAL_TECHNIQUE_LETTER` is
what it went by before `--eval` existed, kept so that stored sessions still read.

The three blind techniques retrieve a character at a time and bisect on its ordinal. The payload
therefore asks a yes/no question, and the technique's own channel - a delay, a file, a request made
elsewhere - carries the yes.

## Building the payload

A command becomes a payload by being wrapped and carried.

**Boundaries.** `settings.PREFIXES`, `SUFFIXES` and `SEPARATORS`, narrowed to the level in force by
`apply_injection_level()`, which reads them off the `_LVL1/2/3` lists.
`handler.py: _boundary_combinations()` walks every combination worth sending and drops the ones that
collapse onto something already tried - a prefix that is itself a separator arrives as the empty
prefix that was tried first, and a suffix is dead against a payload that has already closed itself.

**Choosing among them.** `--test-filter` and `--test-skip`, through `checks.test_selected()`, asked
of every boundary rather than of the technique as a whole.

**Whitespace.** `settings.WHITESPACES`, which a tamper script is allowed to rewrite.

**Tampering.** One script per file in `src/tamper/`. A script defines `tamper(payload)` and hands it
back rewritten. Where a script needs the whole request instead of the payload, `xforwardedfor.py` is
the precedent, hooked in `headers.do_check()`. `checks.tamper_scripts()` loads them and
`perform_payload_modification()` applies them in order.

**Carriers.** Where the parameter's value arrived written in something - Base64, hex, whatever
`--param-encoding` names or detection worked out - the payload is written out the same way. A value
answered in a different encoding from the one it came in is not that parameter's value.

## Getting it there and back

`src/core/requests/`

Every request leaves through one door. `headers.check_http_traffic()` builds the opener, applies the
policy, sends, reads and logs. A caller that wants to read or time the answer itself goes through
`headers.send_raw()`, which still applies the policy and is still counted. `requests.py` is what the
rest of the code actually calls: `get_request_response()`, the per-technique request builders, the
page-stability check.

Two things to know before changing anything here, both learned the hard way:

- **`settings.TOTAL_OF_REQUESTS` is not just a tally.** `stability.should_keep_retrying()`,
  `expand_retry_budget()` and `request_was_retried()` all read it. Count a request without growing
  the budget beside it and the retry loop starves - after which every later request quietly falls
  through to a bare fallback, taking the traffic log, the proxy and the redirect handling with it.
- **What is applied to one request path has to be applied to all of them.** `--retry-on` was once
  honoured on the technique's requests but not on the two samples the stability check compares, and
  that alone was enough to make a target that refuses at random look uninjectable: the two samples
  differed, so the element the result prints into was set aside as noise for the rest of the run.

The rest is one concern per file - `anticsrf.py`, `authentication.py`, `cookies.py`,
`redirection.py`, `keepalive.py`, `chunked.py`, `proxy.py`, `tor.py`, `hooks.py` for
`--preprocess`/`--postprocess`, `mining.py` for `--mine-params`/`--mine-endpoints`, and
`reproduce.py`, which writes a finding out as a command you can run yourself.

### What a body is made of

`parameters.py` decides what counts as a parameter. A POST body is recognised by its shape and split
accordingly, in `configure_post_data_format()` and `split_post_parameters()`:

| Shape | Flag | Split into |
|-------|------|------------|
| form | - | `name=value` pairs |
| JSON | `IS_JSON` | members, flattened, named by the path they sit at |
| SOAP/XML | `IS_XML` | elements, keeping the layout so the document can be rebuilt |
| GraphQL | `IS_GRAPHQL` | the document cut after each argument, so the pieces joined are the document again |

A structured body is never form-encoded. It escapes for its own syntax and goes out under its own
content type, because a percent-encoded payload inside a JSON string is not a payload any more.

## Deciding what it means

`src/core/controller/checks.py` is the biggest file in the tree and holds everything that is not one
technique's business: the heuristics, the false-positive re-check, page comparison and dynamic-region
marking, protection handling, option validation, and the wording of what gets reported.

For one parameter the order is: whether it is dynamic at all (`--skip-static`), whether it is worth
the full set (the heuristic), then technique after technique until one confirms - and then the
finding is re-proved before anybody is told about it.

## Once it works

| File | What it does |
|------|--------------|
| `controller/handler.py` | runs a command through the confirmed point and reads the output back |
| `controller/injector.py` | the retrieval loop, threaded where the technique allows |
| `controller/enumeration.py` | the target facts `--all` and its friends ask for |
| `controller/file_access.py` | `--file-read`, `--file-write`, `--file-dest` |
| `controller/shell_options.py` | the `--os-shell` prompt |
| `controller/proof.py` | `--proof` - re-prove every finding and write the transcript beside the output |
| `core/shells/` | the shells themselves: reverse and bind TCP, the relay, the modes |

## What survives

**Within a run**, from one target to the next: nothing learned about one may read as true of
another. `settings.reset_target_state()` records a baseline the first time it runs and restores it
for every target after. `RUN_WIDE_STATE` names what is exempt - what the user asked for, what has
been answered once and should not be asked again, the tallies kept across targets. Everything else
is per-target, and **a new name is per-target unless it is listed**; the omission that used to leak
is now the safe direction. `RESTORED_OPTIONS` covers the options a target's own testing can change
and which the next target is entitled to see as the user left them.

**Between runs**: `src/utils/session_handler.py`, one SQLite file per target holding the injection
points and what was learned, which is why a second run answers at once. `--flush-session` discards
it, `--ignore-session` leaves it in place and ignores it.

**On disk**: `.output/<host>_<port>/` (`settings.OUTPUT_DIR`), with `logs.py` writing the run's own
log, `--report-json` and `--results-file`; `-t` writing the HTTP traffic from `headers.py`, and
`--har` writing it through `src/utils/har.py`.

## Where things live

| Path | What is in it |
|------|---------------|
| `src/core/main.py` | the run |
| `src/core/parse/` | the command line, the configuration file, a raw request file |
| `src/core/controller/` | orchestration, detection, exploitation, enumeration, proof |
| `src/core/requests/` | everything that reaches the network, and what a parameter is |
| `src/core/techniques/` | one package per technique |
| `src/core/eval/` | the evaluator sink - its grammars and its payloads |
| `src/core/oob/` | the out-of-band channel, its provider and its keys |
| `src/core/shells/` | interactive shells and the TCP handlers |
| `src/core/modules/` | injection that needs no ordinary parameter |
| `src/tamper/` | payload-rewriting scripts |
| `src/utils/` | settings, session, logs, crawler, progress, install, update |
| `src/thirdparty/` | bundled libraries, so that a run needs nothing installed |
| `data/txt/` | word lists read at runtime |

Two objects carry the run, and neither is passed around - both are imported where they are read.
`src/utils/settings.py` holds the constants and the mutable run state, and is where a new constant
goes. `menu.options` holds what the user asked for, as `optparse` produced it.

Names are `lower_snake_case`, constants `UPPERCASE`, indentation is two spaces, and every comment
and docstring is one line.

## Adding something

| To add | Start at |
|--------|----------|
| an option | `parse/cmdline.py`, then `core/options.py: validate()` for combinations that cannot hold |
| a constant | `utils/settings.py` |
| a tamper script | a file in `src/tamper/`, then the registry in `settings.TAMPER_SCRIPTS` |
| a technique | a package under `core/techniques/`, then `execution.select_injector()` and `settings.TECHNIQUE_ORDER` |
| a language for `--eval` | a module in `core/eval/grammars/` |
| a body format | `parameters.configure_post_data_format()` and `split_post_parameters()` |
| a module | the `MODULES` map in `core/modules/modules_handler.py`, and `settings.MODULES` |

And when something is already wrong: the wire is `requests/headers.py`, whether a parameter was
tested at all is `controller.py: perform_checks()`, whether a finding was believed is `checks.py`,
what a run remembers is `session_handler.py`, and state bleeding from one target into the next is
`settings.RUN_WIDE_STATE`.
