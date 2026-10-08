// The release canary's chat-turn journey (DR-0457).
//
// Injected by the shell into the real window only when GAUGEDESK_TEST_SIGNIN=1
// admitted a fresh data directory and GAUGEDESK_TEST_JOURNEY named a plan
// (src/test_journey.rs). The plan is `window.__gwTestJourney`:
//
//   callback  gaugewright://auth/callback#code=… — the one-time code the canary
//             obtained by signing in with a passkey, bound to the verifier the
//             shell seeded as this desktop's pending attempt
//   message   what to send
//   reply     optional; the exact reply the turn must end with
//   project   optional { id } or { name }; else the first project the window
//             lists that can start a chat
//   model     optional { provider, id, baseUrl, token }: link this provider
//             as Settings does and pick it in the composer before sending
//   ceilings  optional { readyMs, signinMs, chatReadyMs, replyMs }
//
// It does what a person does, in this window's own WebKit: the sign-in code
// arrives through the window's deep-link handler, a new chat is started from
// the project's row, the message is typed into the composer and sent with
// Enter, and the assistant's reply is read from the transcript. Every request
// the window makes that fails or is refused is recorded — method, origin and
// path, status or error — because a refused CORS preflight shows in the page
// only as "Load failed" (gaugedesk-src #1311). A page cannot read a cross-origin
// response's Access-Control-Allow-Origin, so a refused preflight shows here as
// the request's error, not as a header.
//
// Each step is reported through the shell as it happens, one JSON object per
// report, so a report survives the reload a sign-in causes. The last is
// { kind: "outcome", passed, … }. Nothing reported carries the code, the
// provider token, a session or a query string.
(function () {
  "use strict";
  var plan = window.__gwTestJourney;
  if (!plan || window.top !== window) return;

  var CP = plan.controlPlane || "http://127.0.0.1:7878";
  var PHASE = "gw.test-journey.phase";
  var MARK = "gw.test-journey.started-ms";
  var ceilings = {
    readyMs: 120000,
    signinMs: 120000,
    chatReadyMs: 240000,
    replyMs: 120000,
  };
  Object.keys(plan.ceilings || {}).forEach(function (key) {
    ceilings[key] = plan.ceilings[key];
  });

  function invoke(command, args) {
    return window.__TAURI_INTERNALS__.invoke(command, args || {});
  }

  function report(event) {
    try {
      return invoke("test_journey_report", { event: event }).catch(function () {});
    } catch (error) {
      return Promise.resolve();
    }
  }

  // Origin and path only: a query can carry a handle, a fragment a code.
  function where(url) {
    try {
      var parsed = new URL(url, location.href);
      return parsed.origin + parsed.pathname;
    } catch (error) {
      return "<unparseable url>";
    }
  }

  // --- every request, before the page makes any ------------------------------
  var rawFetch = window.fetch.bind(window);
  var responses = [];
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || String(input);
    // The shell's own IPC rides fetch to ipc://, and falls back by itself
    // when that is refused; it is not a request the window makes.
    if (/^ipc:/.test(url)) return rawFetch(input, init);
    var method = String((init && init.method) || (input && input.method) || "GET").toUpperCase();
    var begun = Date.now();
    return rawFetch(input, init).then(
      function (response) {
        var path = where(url);
        var chatRoute = /\/(chats|projects)(\/|$)/.test(path) && method !== "GET";
        if (!response.ok || chatRoute) {
          report({
            kind: "request",
            method: method,
            url: path,
            status: response.status,
            ms: Date.now() - begun,
          });
        }
        if (chatRoute) {
          response
            .clone()
            .json()
            .then(
              function (body) {
                responses.push({ method: method, path: path, status: response.status, body: body });
              },
              function () {
                responses.push({ method: method, path: path, status: response.status, body: null });
              }
            );
        }
        return response;
      },
      function (error) {
        report({
          kind: "request",
          method: method,
          url: where(url),
          error: String((error && error.message) || error),
          ms: Date.now() - begun,
        });
        throw error;
      }
    );
  };

  // An error the window throws, which no step catches, is named too.
  window.addEventListener("error", function (event) {
    report({ kind: "page-error", error: String((event && event.message) || "error").slice(0, 300) });
  });
  window.addEventListener("unhandledrejection", function (event) {
    var reason = event && event.reason;
    report({ kind: "page-error", error: String((reason && reason.message) || reason).slice(0, 300) });
  });

  function phase() {
    try {
      return sessionStorage.getItem(PHASE) || "start";
    } catch (error) {
      return "start";
    }
  }

  function setPhase(value) {
    try {
      sessionStorage.setItem(PHASE, value);
    } catch (error) {}
  }

  function startedMs() {
    try {
      var stored = Number(sessionStorage.getItem(MARK));
      if (stored > 0) return stored;
      sessionStorage.setItem(MARK, String(Date.now()));
    } catch (error) {}
    return Date.now();
  }

  function sleep(ms) {
    return new Promise(function (done) {
      setTimeout(done, ms);
    });
  }

  // Resolve with the first truthy answer of `probe`, polled, or reject naming
  // what was being waited for.
  function until(what, ceilingMs, probe, intervalMs) {
    var deadline = Date.now() + ceilingMs;
    return (function poll() {
      return Promise.resolve()
        .then(probe)
        .catch(function () {
          return null;
        })
        .then(function (value) {
          if (value) return value;
          if (Date.now() > deadline) {
            throw new Error("timed out after " + Math.round(ceilingMs / 1000) + " s waiting for " + what);
          }
          return sleep(intervalMs || 250).then(poll);
        });
    })();
  }

  function words(element) {
    return ((element && element.textContent) || "").replace(/\s+/g, " ").trim();
  }

  // What the page is showing as an error, in its own words.
  function shown() {
    var selectors = [
      "[data-composer-error]",
      "[data-action-error]",
      ".line.admitted.error",
      "[data-credential-error]",
      "[data-home-error]",
      ".signin__status",
      ".homegate-error",
      "[data-control-plane-failure]",
    ];
    var found = [];
    selectors.forEach(function (selector) {
      document.querySelectorAll(selector).forEach(function (element) {
        var text = words(element);
        if (text) found.push(selector + ": " + text.slice(0, 300));
      });
    });
    return found;
  }

  var finished = false;
  function finish(outcome) {
    if (finished) return;
    finished = true;
    outcome.kind = "outcome";
    outcome.elapsedMs = Date.now() - startedMs();
    if (!outcome.passed) outcome.shown = shown();
    setPhase("finished");
    report(outcome);
  }

  function step(name, operation) {
    report({ kind: "step", step: name });
    return Promise.resolve()
      .then(operation)
      .catch(function (error) {
        var failure = new Error(String((error && error.message) || error));
        failure.step = name;
        throw failure;
      });
  }

  function operatorHeaders(secret, bearer, mutation) {
    var headers = { "x-gaugedesk-operator": secret };
    if (bearer) headers.authorization = "Bearer " + bearer;
    if (mutation) {
      headers["content-type"] = "application/json";
      headers["idempotency-key"] = "test-journey-" + Date.now() + "-" + Math.random().toString(36).slice(2);
    }
    return headers;
  }

  function hubSession(secret) {
    return rawFetch(CP + "/account/hub-session", { headers: operatorHeaders(secret) }).then(function (response) {
      return response.ok ? response.json() : null;
    });
  }

  function documentReady() {
    if (document.readyState !== "loading") return Promise.resolve();
    return new Promise(function (done) {
      document.addEventListener("DOMContentLoaded", done, { once: true });
    });
  }

  // --- before sign-in: deliver the code as the OS would ----------------------
  function signIn(secret) {
    return step("waiting for the window to draw", function () {
      return until("the window to draw signed out", ceilings.readyMs, function () {
        return document.querySelector("[data-firstrun], [data-signin], .account-bar, .nav-footer");
      });
    })
      .then(function () {
        return step("delivering the sign-in code", function () {
          setPhase("signing-in");
          (window.__gwDeepLinks = window.__gwDeepLinks || []).push(plan.callback);
          window.dispatchEvent(new CustomEvent("gw-deep-link", { detail: plan.callback }));
        });
      })
      .then(function () {
        // The page reloads once its callback has redeemed the code. If it is
        // still here after the ceiling, the sign-in did not finish.
        return sleep(ceilings.signinMs);
      })
      .then(function () {
        var error = new Error("the window did not reload signed in within " + Math.round(ceilings.signinMs / 1000) + " s");
        error.step = "signing in";
        throw error;
      });
  }

  // --- signed in: a new chat, a message, the reply --------------------------
  function pickProject() {
    var rows = Array.prototype.slice.call(document.querySelectorAll(".tree-group[data-project]"));
    var wanted = plan.project || {};
    var candidates = rows.filter(function (row) {
      return row.querySelector('[data-create="new-project-chat"]');
    });
    if (wanted.id) {
      return candidates.filter(function (row) {
        return row.getAttribute("data-project") === wanted.id;
      })[0];
    }
    if (wanted.name) {
      return candidates.filter(function (row) {
        return words(row.querySelector(".node-label")) === wanted.name;
      })[0];
    }
    return candidates[0];
  }

  function listedProjects() {
    return Array.prototype.slice
      .call(document.querySelectorAll(".tree-group[data-project]"))
      .map(function (row) {
        return words(row.querySelector(".node-label")) + " (" + row.getAttribute("data-project") + ")";
      });
  }

  function linkModel(secret) {
    var model = plan.model;
    return invoke("home_session").then(function (bearer) {
      var settingsUrl = CP + "/account/settings";
      return rawFetch(settingsUrl, { headers: operatorHeaders(secret, bearer) })
        .then(function (response) {
          if (!response.ok) throw new Error("reading account settings returned " + response.status);
          return response.json();
        })
        .then(function (body) {
          var key = "model_picker.endpoint_models";
          var declared = {};
          try {
            declared = JSON.parse((body && body.settings && body.settings[key]) || "{}") || {};
          } catch (error) {}
          if (Array.isArray(declared)) declared = { "openai-generic": declared };
          var ids = Array.isArray(declared[model.provider]) ? declared[model.provider] : [];
          if (ids.indexOf(model.id) >= 0) return;
          declared[model.provider] = ids.concat([model.id]);
          return rawFetch(settingsUrl + "/" + encodeURIComponent(key), {
            method: "PUT",
            headers: operatorHeaders(secret, bearer, true),
            body: JSON.stringify({ value: JSON.stringify(declared) }),
          }).then(function (response) {
            if (!response.ok) throw new Error("declaring the model returned " + response.status);
          });
        })
        .then(function () {
          // What Settings → Model access does: the composer's picker offers
          // the providers the account has linked.
          return rawFetch(CP + "/account/credentials", {
            method: "POST",
            headers: operatorHeaders(secret, bearer, true),
            body: JSON.stringify({ provider: model.provider, token: model.token, base_url: model.baseUrl }),
          });
        })
        .then(function (response) {
          if (!response.ok) throw new Error("linking the model returned " + response.status);
        });
    });
  }

  function setText(textarea, value) {
    var setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
    setter.call(textarea, value);
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function pressEnter(textarea) {
    textarea.focus();
    textarea.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", code: "Enter", bubbles: true, cancelable: true })
    );
  }

  function chatTurn(secret) {
    var chat = null;
    var project = null;
    var opened = 0;
    var sent = 0;
    return step("confirming the sign-in", function () {
      return until("the window's account to be signed in", ceilings.readyMs, function () {
        return hubSession(secret).then(function (status) {
          return status && status.linked === true && !status.expired;
        });
      });
    })
      .then(function () {
        setPhase("signed-in");
        return step("finding a project to chat in", function () {
          return until("a project that can start a chat", ceilings.chatReadyMs, pickProject).then(
            function (row) {
              project = row.getAttribute("data-project");
              report({ kind: "step", step: "project chosen", project: project, listed: listedProjects() });
              return row;
            },
            function (error) {
              report({ kind: "step", step: "projects listed", listed: listedProjects() });
              throw error;
            }
          );
        });
      })
      .then(function (row) {
        if (!plan.model) return row;
        return step("linking the model", function () {
          return linkModel(secret);
        }).then(function () {
          return row;
        });
      })
      .then(function (row) {
        return step("starting a new chat in the project", function () {
          var before = responses.length;
          row.querySelector('[data-create="new-project-chat"]').click();
          return until("the new chat", 30000, function () {
            // A project with a default placement starts its chat there; one
            // without, such as Personal, starts a plain chat.
            var created = responses.slice(before).filter(function (response) {
              return response.method === "POST"
                && /(\/projects\/[^/]+\/placements\/[^/]+\/chats|\/chats)$/.test(response.path);
            })[0];
            if (!created) return null;
            if (created.status >= 300) throw new Error("creating the chat returned " + created.status);
            var body = created.body || {};
            chat = body.id || (body.chat && body.chat.id) || null;
            if (!/^chat-/.test(chat || "")) throw new Error("creating the chat returned no chat id");
            return chat;
          });
        });
      })
      .then(function () {
        return step("opening the new chat", function () {
          return until("the chat to be ready for its first message", ceilings.chatReadyMs, function () {
            var ready = document.querySelector('[data-testid="stream-ready"]');
            var composer = document.querySelector('[data-desktop-composer] textarea[aria-label="Message"]');
            return ready && composer && !composer.disabled && composer;
          }).then(function (composer) {
            opened = Date.now();
            return composer;
          });
        });
      })
      .then(function (composer) {
        if (!plan.model) return composer;
        return step("choosing the model", function () {
          var option = plan.model.provider + ":" + plan.model.id;
          var before = responses.length;
          var picker = function () {
            return document.querySelector("[data-desktop-composer] [data-model-picker]");
          };
          // A narrow composer folds the model into its "more" menu.
          if (!picker()) {
            var more = document.querySelector("[data-desktop-composer] [data-composer-more]");
            if (more) more.click();
          }
          return until("the composer's model picker", 15000, picker)
            .then(function (found) {
              found.click();
              return until("the model option " + option, 15000, function () {
                return document.querySelector('[data-model-option="' + option + '"]');
              });
            })
            .then(function (choice) {
              choice.click();
              return until("the chat's model to be saved", 30000, function () {
                var saved = responses.slice(before).filter(function (response) {
                  return response.method === "PUT" && response.path.slice(-("/chats/" + chat + "/config").length) === "/chats/" + chat + "/config";
                })[0];
                if (saved && saved.status >= 400) throw new Error("saving the chat's model returned " + saved.status);
                return saved;
              });
            })
            .then(function () {
              return document.querySelector('[data-desktop-composer] textarea[aria-label="Message"]');
            });
        });
      })
      .then(function (composer) {
        return step("sending the first message", function () {
          setText(composer, plan.message || "Desktop chat-turn canary: reply in one sentence.");
          sent = Date.now();
          pressEnter(composer);
        });
      })
      .then(function () {
        return step("waiting for the assistant's reply", function () {
          return until("the assistant's reply", ceilings.replyMs, function () {
            var failed = document.querySelector('.line.admitted.error, [data-credential-error], [data-action-error="chat"]');
            if (failed) throw new Error("the turn ended in an error: " + words(failed).slice(0, 300));
            var lines = document.querySelectorAll(".line.admitted.assistant[data-line-text]");
            var last = lines[lines.length - 1];
            var text = last && last.getAttribute("data-line-text");
            return text && text.replace(/\s+/g, " ").trim();
          }).then(function (reply) {
            if (plan.reply && reply !== plan.reply) {
              throw new Error('the assistant replied "' + reply.slice(0, 200) + '", not the expected sentence');
            }
            var task = responses.filter(function (response) {
              return response.method === "POST" && /\/chats\/[^/]+\/task$/.test(response.path);
            }).pop();
            finish({
              passed: true,
              chat: chat,
              project: project,
              reply: reply,
              runPhase: task && task.body && task.body.run_phase,
              readyMs: opened ? opened - startedMs() : null,
              replyMs: Date.now() - sent,
            });
          });
        });
      });
  }

  documentReady()
    .then(function () {
      return until("the control plane's secret", ceilings.readyMs, function () {
        return invoke("operator_secret");
      });
    })
    .then(function (secret) {
      var current = phase();
      startedMs();
      report({ kind: "load", phase: current });
      if (current === "finished") return;
      if (current === "start") return signIn(secret);
      return chatTurn(secret);
    })
    .catch(function (error) {
      finish({ passed: false, step: error.step || "starting", error: String((error && error.message) || error) });
    });
})();
