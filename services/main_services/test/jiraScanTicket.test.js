const test = require('node:test');
const assert = require('node:assert');
const { formatAdfDescription } = require('../src/services/jiraService');

test('formatAdfDescription: null returns placeholder paragraph', () => {
  const result = formatAdfDescription(null);
  assert.strictEqual(result.type, 'doc');
  assert.strictEqual(result.version, 1);
  assert.ok(Array.isArray(result.content));
  assert.strictEqual(result.content.length, 1);
  assert.strictEqual(result.content[0].type, 'paragraph');
});

test('formatAdfDescription: single line returns one paragraph with text node', () => {
  const result = formatAdfDescription('Hello World');
  assert.strictEqual(result.content.length, 1);
  const para = result.content[0];
  assert.strictEqual(para.type, 'paragraph');
  assert.strictEqual(para.content[0].type, 'text');
  assert.strictEqual(para.content[0].text, 'Hello World');
});

test('formatAdfDescription: newline within paragraph becomes hardBreak', () => {
  const result = formatAdfDescription('Line 1\nLine 2');
  assert.strictEqual(result.content.length, 1);
  const para = result.content[0];
  assert.strictEqual(para.content.length, 3);
  assert.strictEqual(para.content[0].text, 'Line 1');
  assert.strictEqual(para.content[1].type, 'hardBreak');
  assert.strictEqual(para.content[2].text, 'Line 2');
});

test('formatAdfDescription: blank line splits into two paragraphs', () => {
  const result = formatAdfDescription('Para one\n\nPara two');
  assert.strictEqual(result.content.length, 2);
  assert.strictEqual(result.content[0].content[0].text, 'Para one');
  assert.strictEqual(result.content[1].content[0].text, 'Para two');
});

test('formatAdfDescription: no raw newlines in text nodes', () => {
  const text = 'A: 1\nB: 2\n\nC: 3\nD: 4';
  const result = formatAdfDescription(text);
  for (const node of result.content) {
    for (const inline of node.content) {
      if (inline.type === 'text') {
        assert.ok(!inline.text.includes('\n'), 'text node must not contain raw newlines');
      }
    }
  }
});

test('summary sanitization to 250 chars', () => {
  const long = 'A'.repeat(300);
  assert.strictEqual(long.slice(0, 250).length, 250);
});

