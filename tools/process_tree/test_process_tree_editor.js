const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const editor = require('../../apps/spl_process_tree_lab/appserver/static/js/process_tree_104.js');

const suffix = '| search Image="*\\\\cmd.exe" | where User!="SYSTEM"';
assert.strictEqual(editor.DEFAULT_FILTER_SPL, '| search *');
assert.deepStrictEqual(editor.validateFilterSpl(''), { ok: true, error: '' });
assert.deepStrictEqual(editor.validateFilterSpl(suffix), { ok: true, error: '' });
for (const invalid of [
  '| search index=*',
  '| search sourcetype=Other',
  '| search source="other"',
  '| search EventCode=3',
  '| collect index=main',
  '| MAP search="| makeresults"',
  '| outputlookup test.csv',
  '| join host [ search index=* ]',
  '| eval host="BSTOLL-L"',
  '| rex mode=sed field=host "s/.*/BSTOLL-L/"',
  '| stats count',
  '`hidden_macro`',
  '[ search index=main ]',
  '``` hidden scope ```'
]) {
  assert.strictEqual(editor.validateFilterSpl(invalid).ok, false, invalid);
}

assert.strictEqual(editor.validateFieldName('ParentImage'), true);
assert.strictEqual(editor.validateFieldName('process.parent.name'), true);
for (const invalid of ['', 'Parent Image', 'foo|collect', '$token$', '1field', 'field-name']) {
  assert.strictEqual(editor.validateFieldName(invalid), false, invalid);
}
assert.deepStrictEqual(
  editor.validateFieldMapping({
    parentImage: 'Creator_Process_Name',
    image: 'New_Process_Name',
    parentPid: 'Creator_Process_ID',
    pid: 'New_Process_ID',
    commandLine: 'Process_Command_Line',
    user: 'SubjectUserName'
  }),
  { ok: true, error: '' }
);
assert.strictEqual(editor.validateFieldMapping({ parentImage: 'foo|collect' }).ok, false);

assert.deepStrictEqual(editor.schemaPresetTokens('security4688'), {
  pt_parent_image_field: 'Creator_Process_Name',
  pt_image_field: 'New_Process_Name',
  pt_parent_pid_field: 'Creator_Process_ID',
  pt_pid_field: 'New_Process_ID',
  pt_command_line_field: 'Process_Command_Line',
  pt_user_field: 'SubjectUserName',
  mapping_ready: 'true'
});
assert.strictEqual(editor.schemaPresetTokens('custom'), null);

const collapseBody = { hidden: false };
const collapseButton = {
  textContent: '',
  attrs: {},
  setAttribute(name, value) { this.attrs[name] = value; }
};
editor.setEditorCollapsed(true, collapseBody, collapseButton);
assert.strictEqual(collapseBody.hidden, true);
assert.strictEqual(collapseButton.attrs['aria-expanded'], 'false');
assert.strictEqual(collapseButton.textContent, 'Expand');
editor.setEditorCollapsed(false, collapseBody, collapseButton);
assert.strictEqual(collapseBody.hidden, false);
assert.strictEqual(collapseButton.attrs['aria-expanded'], 'true');
assert.strictEqual(collapseButton.textContent, 'Collapse');

const indexResets = editor.cascadeResetTokens('data_index');
for (const token of [
  'data_sourcetype', 'form.data_sourcetype', 'data_source', 'form.data_source',
  'data_eventcode', 'form.data_eventcode', 'host', 'form.host', 'root_guid',
  'form.root_guid', 'pstree_pid', 'form.pstree_pid', 'schema_mode',
  'form.schema_mode', 'show_pstree', 'mapping_ready', 'custom_mapping'
]) {
  assert.ok(indexResets.includes(token), token);
}
assert.deepStrictEqual(editor.cascadeResetTokens('unknown'), []);

const segments = editor.splitPipeline('| search CommandLine="one|two" | rex field=Image "x"');
assert.strictEqual(segments.length, 3);
assert.strictEqual(segments[1].trim(), 'search CommandLine="one|two"');

assert.strictEqual(editor.normalizeNodeMode('application'), 'application');
assert.strictEqual(editor.normalizeNodeMode('pid'), 'pid');
assert.strictEqual(editor.normalizeNodeMode('anything'), 'application');

const browserSource = fs.readFileSync(
  require.resolve('../../apps/spl_process_tree_lab/appserver/static/js/process_tree_104.js'),
  'utf8'
);
const browserListeners = {};
function interactiveElement(id, initial = {}) {
  return Object.assign(initial, {
    id,
    addEventListener(event, callback) { browserListeners[id + ':' + event] = callback; }
  });
}
const browserElements = {
  'process-tree-base-spl': interactiveElement('process-tree-base-spl', { value: '', focus() {} }),
  'process-tree-apply-spl': interactiveElement('process-tree-apply-spl'),
  'process-tree-reset-spl': interactiveElement('process-tree-reset-spl'),
  'process-tree-toggle-spl': interactiveElement('process-tree-toggle-spl', {
    textContent: 'Collapse',
    attrs: {},
    setAttribute(name, value) { this.attrs[name] = value; }
  }),
  'process-tree-filter-body': { hidden: false },
  'process-tree-editor-status': { textContent: '', className: '' },
  'custom-parent-image': { value: 'Creator_Process_Name' },
  'custom-image': { value: 'New_Process_Name' },
  'custom-parent-pid': { value: 'Creator_Process_ID' },
  'custom-pid': { value: 'New_Process_ID' },
  'custom-command-line': { value: 'Process_Command_Line' },
  'custom-user': { value: 'SubjectUserName' },
  'apply-custom-mapping': interactiveElement('apply-custom-mapping'),
  'custom-mapping-status': { textContent: '', className: '' }
};
const tokenValues = { default: { schema_mode: 'security4688' }, submitted: {} };
const sessionValues = {};
const browserWindow = {
  document: {
    readyState: 'complete',
    getElementById(id) { return browserElements[id] || null; },
    addEventListener(event, callback) { browserListeners['document:' + event] = callback; }
  },
  sessionStorage: {
    getItem(key) { return sessionValues[key] || null; },
    setItem(key, value) { sessionValues[key] = value; }
  },
  require(dependencies, success) {
    success({
      Components: {
        get(name) {
          return {
            set(key, value) { tokenValues[name][key] = value; },
            unset(key) { delete tokenValues[name][key]; },
            get(key) { return tokenValues[name][key]; },
            on() {}
          };
        }
      }
    });
  }
};
const browserContext = { window: browserWindow, globalThis: browserWindow };
vm.runInNewContext(browserSource, browserContext);
assert.strictEqual(tokenValues.submitted.pt_parent_image_field, 'Creator_Process_Name');
assert.strictEqual(tokenValues.submitted.mapping_ready, 'true');
assert.strictEqual(browserElements['process-tree-base-spl'].value, '| search *');
assert.match(browserElements['process-tree-editor-status'].textContent, /optional filter SPL/i);
browserListeners['process-tree-toggle-spl:click']();
assert.strictEqual(browserElements['process-tree-filter-body'].hidden, true);
assert.strictEqual(browserElements['process-tree-toggle-spl'].textContent, 'Expand');
assert.strictEqual(sessionValues[editor.COLLAPSE_STORAGE_KEY], 'true');
browserListeners['process-tree-toggle-spl:click']();
assert.strictEqual(browserElements['process-tree-filter-body'].hidden, false);
browserElements['process-tree-base-spl'].value = suffix;
browserListeners['process-tree-apply-spl:click']();
assert.strictEqual(tokenValues.default.filter_spl, suffix);
assert.strictEqual(tokenValues.submitted.filter_spl, suffix);
assert.match(browserElements['process-tree-editor-status'].textContent, /Filter SPL applied/);

browserListeners['document:click']({ target: browserElements['apply-custom-mapping'] });
assert.strictEqual(tokenValues.default.pt_parent_image_field, 'Creator_Process_Name');
assert.strictEqual(tokenValues.submitted.pt_image_field, 'New_Process_Name');
assert.strictEqual(tokenValues.submitted.pt_parent_pid_field, 'Creator_Process_ID');
assert.strictEqual(tokenValues.submitted.pt_pid_field, 'New_Process_ID');
assert.strictEqual(tokenValues.submitted.pt_command_line_field, 'Process_Command_Line');
assert.strictEqual(tokenValues.submitted.pt_user_field, 'SubjectUserName');
assert.strictEqual(tokenValues.submitted.mapping_ready, 'true');
assert.match(browserElements['custom-mapping-status'].textContent, /Custom mapping applied/);

browserElements['custom-parent-image'].value = 'host|collect';
browserListeners['document:click']({ target: browserElements['apply-custom-mapping'] });
assert.strictEqual(tokenValues.default.mapping_ready, undefined);
assert.strictEqual(tokenValues.submitted.mapping_ready, undefined);
assert.match(browserElements['custom-mapping-status'].textContent, /Invalid parent process/);

console.log('process_tree editor unit checks passed');
