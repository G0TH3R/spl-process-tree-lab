(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(root);
    return;
  }
  const api = factory(root);
  root.ProcessTreeEditor = api;
  if (root.document.readyState === "loading") {
    root.document.addEventListener("DOMContentLoaded", api.init, { once: true });
  } else {
    api.init();
  }
}(typeof window !== "undefined" ? window : globalThis, function (root) {
  "use strict";

  const DEFAULT_FILTER_SPL = "| search *";
  const STORAGE_KEY = "spl_process_tree_lab.filter_spl.v100";
  const COLLAPSE_STORAGE_KEY = "spl_process_tree_lab.filter_collapsed.v104";
  const ALLOWED_FILTER_COMMANDS = new Set(["search", "where"]);
  const RESET_CHAINS = Object.freeze({
    data_index: ["data_sourcetype", "data_source", "data_eventcode", "host", "root_guid", "pstree_pid", "schema_mode", "show_pstree", "mapping_ready", "custom_mapping"],
    data_sourcetype: ["data_source", "data_eventcode", "host", "root_guid", "pstree_pid", "schema_mode", "show_pstree", "mapping_ready", "custom_mapping"],
    data_source: ["data_eventcode", "host", "root_guid", "pstree_pid", "schema_mode", "show_pstree", "mapping_ready", "custom_mapping"],
    data_eventcode: ["host", "root_guid", "pstree_pid", "schema_mode", "show_pstree", "mapping_ready", "custom_mapping"]
  });
  const SCHEMA_PRESETS = Object.freeze({
    sysmon: Object.freeze({
      pt_parent_image_field: "ParentImage", pt_image_field: "Image",
      pt_parent_pid_field: "ParentProcessId", pt_pid_field: "ProcessId",
      pt_command_line_field: "CommandLine", pt_user_field: "User",
      mapping_ready: "true"
    }),
    security4688: Object.freeze({
      pt_parent_image_field: "Creator_Process_Name", pt_image_field: "New_Process_Name",
      pt_parent_pid_field: "Creator_Process_ID", pt_pid_field: "New_Process_ID",
      pt_command_line_field: "Process_Command_Line", pt_user_field: "SubjectUserName",
      mapping_ready: "true"
    })
  });
  const FORBIDDEN_COMMANDS = new Set([
    "append", "appendcols", "appendpipe", "collect", "delete", "dump", "join",
    "map", "mcollect", "meventcollect", "multisearch", "outputcsv",
    "outputlookup", "run", "script", "sendalert", "sendemail",
    "runshellscript", "set", "tscollect", "union"
  ]);

  function splitPipeline(query) {
    const segments = [];
    let current = "";
    let quote = null;
    let escaped = false;
    let inComment = false;

    for (let i = 0; i < String(query || "").length; i += 1) {
      const ch = query[i];
      const triple = query.slice(i, i + 3) === "```";
      if (!quote && triple) {
        inComment = !inComment;
        current += "```";
        i += 2;
        continue;
      }
      if (!inComment && quote) {
        current += ch;
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === quote) quote = null;
        continue;
      }
      if (!inComment && (ch === '"' || ch === "'")) {
        quote = ch;
        current += ch;
        continue;
      }
      if (!inComment && ch === "|") {
        segments.push(current);
        current = "";
        continue;
      }
      current += ch;
    }
    segments.push(current);
    return segments;
  }

  function commandName(segment) {
    const uncommented = String(segment || "").replace(/```[\s\S]*?```/g, " ").trim();
    const match = uncommented.match(/^([A-Za-z][A-Za-z0-9_]*)/);
    return match ? match[1].toLowerCase() : "";
  }

  function containsKeywordOutsideQuotes(text, keyword) {
    let quote = null;
    let escaped = false;
    let token = "";
    const words = [];
    for (const ch of String(text || "")) {
      if (quote) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'") {
        if (token) { words.push(token); token = ""; }
        quote = ch;
      } else if (/[A-Za-z0-9_]/.test(ch)) token += ch;
      else if (token) { words.push(token); token = ""; }
    }
    if (token) words.push(token);
    return words.some(function (word) { return word.toLowerCase() === keyword; });
  }

  function validateFilterSpl(query) {
    const normalized = String(query || "").trim().replace(/\s+/g, " ");
    if (!normalized) return { ok: true, error: "" };
    if (/[`\[\]]/.test(normalized) || normalized.includes("```")) {
      return { ok: false, error: "Macros, comments, and subsearch brackets are not allowed in filter SPL." };
    }
    if (/\b(?:index|sourcetype|source|eventcode)\s*=/i.test(normalized)) {
      return { ok: false, error: "Data scope belongs in the cascading selectors, not filter SPL." };
    }
    if (!normalized.startsWith("|")) {
      return { ok: false, error: "Filter SPL must begin with a pipe." };
    }
    const segments = splitPipeline(normalized);
    for (let i = 1; i < segments.length; i += 1) {
      const command = commandName(segments[i]);
      if (FORBIDDEN_COMMANDS.has(command)) {
        return { ok: false, error: "Blocked action or fan-out command: " + command };
      }
      if (!ALLOWED_FILTER_COMMANDS.has(command)) {
        return { ok: false, error: "Filter command is not allowlisted: " + command };
      }
    }
    return { ok: true, error: "" };
  }

  function validateFieldName(value) {
    return /^[A-Za-z_][A-Za-z0-9_.]*$/.test(String(value || ""));
  }

  function validateFieldMapping(mapping) {
    const labels = {
      parentImage: "parent process name/path",
      image: "child process name/path",
      parentPid: "parent PID",
      pid: "child PID",
      commandLine: "command line",
      user: "user"
    };
    for (const key of Object.keys(labels)) {
      if (!validateFieldName(mapping && mapping[key])) {
        return { ok: false, error: "Invalid " + labels[key] + " field name." };
      }
    }
    return { ok: true, error: "" };
  }

  function cascadeResetTokens(upstream) {
    const downstream = RESET_CHAINS[upstream] || [];
    const tokens = [];
    downstream.forEach(function (token) {
      tokens.push(token);
      if (!["show_pstree", "mapping_ready", "custom_mapping"].includes(token)) {
        tokens.push("form." + token);
      }
    });
    return tokens;
  }

  function schemaPresetTokens(mode) {
    const preset = SCHEMA_PRESETS[mode];
    return preset ? Object.assign({}, preset) : null;
  }

  function setEditorCollapsed(collapsed, body, button) {
    body.hidden = Boolean(collapsed);
    button.setAttribute("aria-expanded", collapsed ? "false" : "true");
    button.textContent = collapsed ? "Expand" : "Collapse";
  }

  function normalizeNodeMode(value) {
    return value === "pid" ? "pid" : "application";
  }

  let initialized = false;

  function init() {
    if (initialized || !root.document) return initialized;
    const editor = root.document.getElementById("process-tree-base-spl");
    const apply = root.document.getElementById("process-tree-apply-spl");
    const reset = root.document.getElementById("process-tree-reset-spl");
    const toggle = root.document.getElementById("process-tree-toggle-spl");
    const editorBody = root.document.getElementById("process-tree-filter-body");
    const status = root.document.getElementById("process-tree-editor-status");
    if (!editor || !apply || !reset || !toggle || !editorBody || !status) return false;
    initialized = true;
    let initial = DEFAULT_FILTER_SPL;
    try {
      initial = root.sessionStorage.getItem(STORAGE_KEY) || DEFAULT_FILTER_SPL;
    } catch (error) {
      initial = DEFAULT_FILTER_SPL;
    }
    editor.value = initial;
    let collapsed = false;
    try { collapsed = root.sessionStorage.getItem(COLLAPSE_STORAGE_KEY) === "true"; } catch (error) { /* optional */ }
    setEditorCollapsed(collapsed, editorBody, toggle);

    function setStatus(message, isError) {
      status.textContent = message;
      status.className = isError ? "pt-editor-status pt-error" : "pt-editor-status pt-ok";
    }

    function applyQuery() {
      const query = editor.value.trim();
      const validation = validateFilterSpl(query);
      if (!validation.ok) {
        setStatus(validation.error, true);
        return false;
      }
      if (typeof root.require !== "function") {
        setStatus("Splunk MVC is unavailable; reload the dashboard and try again.", true);
        return false;
      }
      setStatus("Applying filter SPL...", false);
      root.require(
        ["splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"],
        function (mvc) {
          const defaultTokens = mvc.Components.get("default");
          const submittedTokens = mvc.Components.get("submitted");
          if (!defaultTokens || !submittedTokens) {
            setStatus("Splunk token models are unavailable; reload the dashboard.", true);
            return;
          }
          defaultTokens.set("filter_spl", query);
          submittedTokens.set("filter_spl", query);
          try { root.sessionStorage.setItem(STORAGE_KEY, query); } catch (error) { /* optional */ }
          setStatus("Filter SPL applied to all panels. Use Submit after changing dashboard controls.", false);
        },
        function () {
          setStatus("Splunk MVC failed to load; reload the dashboard.", true);
        }
      );
      return true;
    }

    apply.addEventListener("click", applyQuery);
    reset.addEventListener("click", function () {
      editor.value = DEFAULT_FILTER_SPL;
      applyQuery();
    });
    toggle.addEventListener("click", function () {
      collapsed = !collapsed;
      setEditorCollapsed(collapsed, editorBody, toggle);
      try { root.sessionStorage.setItem(COLLAPSE_STORAGE_KEY, String(collapsed)); } catch (error) { /* optional */ }
      if (!collapsed && typeof editor.focus === "function") editor.focus();
    });
    editor.addEventListener("keydown", function (event) {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        applyQuery();
      }
    });
    if (typeof root.require === "function") {
      root.require(
        ["splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"],
        function (mvc) {
          const defaultTokens = mvc.Components.get("default");
          const submittedTokens = mvc.Components.get("submitted");
          if (!defaultTokens || !submittedTokens || typeof defaultTokens.on !== "function") return;
          Object.keys(RESET_CHAINS).forEach(function (upstream) {
            defaultTokens.on("change:" + upstream, function () {
              cascadeResetTokens(upstream).forEach(function (token) {
                defaultTokens.unset(token);
                submittedTokens.unset(token);
              });
            });
          });
          function applySchemaMode(mode) {
            const models = [defaultTokens, submittedTokens];
            models.forEach(function (model) {
              model.unset("mapping_ready");
              model.unset("custom_mapping");
            });
            const preset = schemaPresetTokens(mode);
            if (!preset) {
              if (mode === "custom") {
                models.forEach(function (model) { model.set("custom_mapping", "true"); });
              }
              return;
            }
            models.forEach(function (model) {
              Object.keys(preset).forEach(function (key) { model.set(key, preset[key]); });
            });
          }
          applySchemaMode(defaultTokens.get("schema_mode") || "sysmon");
          defaultTokens.on("change:schema_mode", function (model, mode) {
            applySchemaMode(mode);
          });
        }
      );
    }
    root.document.addEventListener("click", function (event) {
      if (!event.target || event.target.id !== "apply-custom-mapping") return;
      const mappingStatus = root.document.getElementById("custom-mapping-status");
      const mapping = {
        parentImage: (root.document.getElementById("custom-parent-image") || {}).value,
        image: (root.document.getElementById("custom-image") || {}).value,
        parentPid: (root.document.getElementById("custom-parent-pid") || {}).value,
        pid: (root.document.getElementById("custom-pid") || {}).value,
        commandLine: (root.document.getElementById("custom-command-line") || {}).value,
        user: (root.document.getElementById("custom-user") || {}).value
      };
      if (typeof root.require !== "function") {
        if (mappingStatus) {
          mappingStatus.textContent = "Splunk MVC is unavailable; reload the dashboard.";
          mappingStatus.className = "pt-editor-status pt-error";
        }
        return;
      }
      root.require(
        ["splunkjs/mvc", "splunkjs/mvc/simplexml/ready!"],
        function (mvc) {
          const models = [mvc.Components.get("default"), mvc.Components.get("submitted")];
          if (!models[0] || !models[1]) return;
          models.forEach(function (model) { model.unset("mapping_ready"); });
          const validation = validateFieldMapping(mapping);
          if (!validation.ok) {
            if (mappingStatus) {
              mappingStatus.textContent = validation.error;
              mappingStatus.className = "pt-editor-status pt-error";
            }
            return;
          }
          const tokens = {
            pt_parent_image_field: mapping.parentImage,
            pt_image_field: mapping.image,
            pt_parent_pid_field: mapping.parentPid,
            pt_pid_field: mapping.pid,
            pt_command_line_field: mapping.commandLine,
            pt_user_field: mapping.user,
            mapping_ready: "true"
          };
          models.forEach(function (model) {
            Object.keys(tokens).forEach(function (key) { model.set(key, tokens[key]); });
          });
          if (mappingStatus) {
            mappingStatus.textContent = "Custom mapping applied. Submit the dashboard to run.";
            mappingStatus.className = "pt-editor-status pt-ok";
          }
        }
      );
    });
    setStatus("Enter optional filter SPL, then press Apply SPL or Cmd/Ctrl+Enter.", false);
    return true;
  }

  return {
    DEFAULT_FILTER_SPL,
    COLLAPSE_STORAGE_KEY,
    ALLOWED_FILTER_COMMANDS,
    RESET_CHAINS,
    SCHEMA_PRESETS,
    FORBIDDEN_COMMANDS,
    splitPipeline,
    containsKeywordOutsideQuotes,
    validateFilterSpl,
    validateFieldName,
    validateFieldMapping,
    cascadeResetTokens,
    schemaPresetTokens,
    setEditorCollapsed,
    normalizeNodeMode,
    init
  };
}));
