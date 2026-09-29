import test from "node:test"
import assert from "node:assert/strict"

import plugin from "../dist/index.js"

const AWS = "AKIAIOSFODNN7EXAMPLE"
const GH = "ghp_" + "a".repeat(36)
const OPENAI = "sk-proj-" + "a".repeat(40)

const TOKEN_RE = /\[REDACTED:[a-z0-9-]+:[0-9a-f]{12}\]/

async function setUp() {
  const hooks = new Map()
  const ctx = {
    session: {
      hook(name, cb) {
        hooks.set(name, cb)
        return Promise.resolve()
      },
    },
    tool: {
      hook(name, cb) {
        hooks.set(name, cb)
        return Promise.resolve()
      },
    },
  }
  await plugin.setup(ctx)
  return hooks
}

test("registers the prompt, context and execute.before hooks", async () => {
  const hooks = await setUp()
  assert.deepEqual([...hooks.keys()].sort(), ["context", "execute.before", "prompt"])
})

test("prompt hook redacts an AWS access key", async () => {
  const hooks = await setUp()
  const event = { prompt: { text: `deploy with ${AWS} now` } }
  hooks.get("prompt")(event)
  assert.match(event.prompt.text, TOKEN_RE)
  assert.ok(!event.prompt.text.includes(AWS))
})

test("prompt hook redacts a password assignment", async () => {
  const hooks = await setUp()
  const event = { prompt: { text: "password: hunter2secret" } }
  hooks.get("prompt")(event)
  assert.match(event.prompt.text, /^password: \[REDACTED:credential:[0-9a-f]{12}\]$/)
})

test("the same secret always yields the same token", async () => {
  const hooks = await setUp()
  const first = { prompt: { text: `key ${AWS}` } }
  const second = { prompt: { text: `again ${AWS}` } }
  hooks.get("prompt")(first)
  hooks.get("prompt")(second)
  assert.equal(first.prompt.text.match(TOKEN_RE)[0], second.prompt.text.match(TOKEN_RE)[0])
})

test("context hook redacts system, messages and tool definitions", async () => {
  const hooks = await setUp()
  const event = {
    system: [{ type: "text", text: `openai key ${OPENAI}` }],
    messages: [{ parts: [{ type: "text", text: `github token ${GH}` }] }],
    tools: { read: { description: "read a file", input: {} } },
  }
  hooks.get("context")(event)
  assert.ok(!event.system[0].text.includes(OPENAI))
  assert.ok(!event.messages[0].parts[0].text.includes(GH))
  assert.equal(event.tools.read.description, "read a file")
})

test("context hook leaves plain text untouched", async () => {
  const hooks = await setUp()
  const event = {
    system: [],
    messages: [{ parts: [{ type: "text", text: "hello world" }] }],
    tools: {},
  }
  hooks.get("context")(event)
  assert.equal(event.messages[0].parts[0].text, "hello world")
})

test("execute.before rehydrates a nested object input", async () => {
  const hooks = await setUp()
  const prompt = { prompt: { text: `token ${AWS}` } }
  hooks.get("prompt")(prompt)
  const token = prompt.prompt.text.match(TOKEN_RE)[0]

  const event = { input: { command: `export KEY=${token}` } }
  hooks.get("execute.before")(event)
  assert.ok(event.input.command.includes(AWS))
  assert.ok(!event.input.command.includes(token))
})

test("execute.before rehydrates a string input", async () => {
  const hooks = await setUp()
  const prompt = { prompt: { text: `token ${AWS}` } }
  hooks.get("prompt")(prompt)
  const token = prompt.prompt.text.match(TOKEN_RE)[0]

  const event = { input: `curl -H "Authorization: ${token}"` }
  hooks.get("execute.before")(event)
  assert.ok(event.input.includes(AWS))
  assert.ok(!event.input.includes(token))
})

test("opaque data URIs are never corrupted", async () => {
  const hooks = await setUp()
  const opaque = `data:image/png;base64,${AWS}`
  const event = { messages: [{ parts: [{ type: "text", text: opaque }] }] }
  hooks.get("context")(event)
  assert.equal(event.messages[0].parts[0].text, opaque)
})

test("redaction is idempotent", async () => {
  const hooks = await setUp()
  const event = { prompt: { text: `use ${AWS}` } }
  hooks.get("prompt")(event)
  const once = event.prompt.text
  hooks.get("prompt")(event)
  assert.equal(event.prompt.text, once)
})
