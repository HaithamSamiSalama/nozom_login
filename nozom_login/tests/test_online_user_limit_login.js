"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

function createElement(tagName) {
	const element = {
		tagName: String(tagName).toUpperCase(),
		className: "",
		hidden: false,
		href: "",
		target: "",
		rel: "",
		textContent: "",
		childNodes: [],
		classList: {
			_values: new Set(),
			add(value) {
				this._values.add(value);
			},
			remove(value) {
				this._values.delete(value);
			},
			contains(value) {
				return this._values.has(value);
			},
		},
		appendChild(child) {
			this.childNodes.push(child);
			return child;
		},
		removeChild(child) {
			const index = this.childNodes.indexOf(child);
			if (index >= 0) {
				this.childNodes.splice(index, 1);
			}
			return child;
		},
		focus() {},
	};

	Object.defineProperty(element, "firstChild", {
		get() {
			return this.childNodes[0] || null;
		},
	});

	return element;
}

function loadApi() {
	const scriptPath = path.join(
		__dirname,
		"..",
		"public",
		"js",
		"online_user_limit_login.js"
	);

	const code = fs.readFileSync(scriptPath, "utf8");
	const sandbox = {
		window: {},
		globalThis: {},
		document: {
			createElement,
			createTextNode(text) {
				return { nodeType: 3, textContent: String(text) };
			},
			getElementById() {
				return null;
			},
			querySelector() {
				return null;
			},
		},
		setTimeout(fn) {
			return 0;
		},
	};

	sandbox.window = sandbox;
	sandbox.globalThis = sandbox;

	vm.runInNewContext(code, sandbox, {
		filename: "online_user_limit_login.js",
	});

	return sandbox.NozomOnlineUserLimitLogin;
}

function collectText(node) {
	if (!node) {
		return "";
	}

	if (node.nodeType === 3) {
		return node.textContent || "";
	}

	const children = node.childNodes || [];
	if (!children.length) {
		return node.textContent || "";
	}

	return children.map(collectText).join("");
}

function findLink(node) {
	if (!node) {
		return null;
	}

	if (node.tagName === "A") {
		return node;
	}

	for (const child of node.childNodes || []) {
		const found = findLink(child);
		if (found) {
			return found;
		}
	}

	return null;
}

const api = loadApi();
let passed = 0;

function test(name, fn) {
	fn();
	passed += 1;
	console.log(`PASS ${name}`);
}

test("ar limit error renders arabic message and ar payment url", () => {
	const container = createElement("div");
	const rendered = api.renderMessage(container, "ar");

	assert.strictEqual(rendered.locale, "ar");
	assert.strictEqual(
		rendered.paymentUrl,
		"https://www.nozom.cloud/ar/dashboard/payments/new"
	);

	const text = collectText(container);
	assert.ok(
		text.includes(
			"تم الوصول إلى الحد الأقصى للمستخدمين المتصلين حاليًا حسب اشتراكك."
		)
	);
	assert.ok(
		text.includes(
			"لترقية اشتراكك وزيادة عدد المستخدمين،"
		)
	);
	assert.ok(text.includes("اضغط هنا"));

	const link = findLink(container);
	assert.ok(link);
	assert.strictEqual(link.textContent, "اضغط هنا");
	assert.strictEqual(
		link.href,
		"https://www.nozom.cloud/ar/dashboard/payments/new"
	);
});

test("en limit error renders english message and en payment url", () => {
	const container = createElement("div");
	const rendered = api.renderMessage(container, "en");

	assert.strictEqual(rendered.locale, "en");
	assert.strictEqual(
		rendered.paymentUrl,
		"https://www.nozom.cloud/en/dashboard/payments/new"
	);

	const text = collectText(container);
	assert.ok(
		text.includes(
			"The maximum number of currently online users allowed by your subscription has been reached."
		)
	);
	assert.ok(
		text.includes(
			"To upgrade your subscription and increase the user limit,"
		)
	);
	assert.ok(text.includes("click here"));

	const link = findLink(container);
	assert.ok(link);
	assert.strictEqual(link.textContent, "click here");
	assert.strictEqual(
		link.href,
		"https://www.nozom.cloud/en/dashboard/payments/new"
	);
});

test("unrelated 401 keeps generic invalid login handler", () => {
	let originalCalled = 0;
	const loginApi = {
		login_handlers: {
			401: function () {
				originalCalled += 1;
			},
		},
	};

	const container = createElement("div");
	container.hidden = false;
	container.appendChild(createElement("p"));

	api.wrapLoginHandlers(loginApi, {
		locale: "en",
		container,
		loginButtonLabel: "Login",
	});

	loginApi.login_handlers[401]({
		responseJSON: {
			message: "Invalid Login",
		},
	});

	assert.strictEqual(originalCalled, 1);
	assert.strictEqual(container.hidden, true);
	assert.strictEqual(container.childNodes.length, 0);
});

test("limit error overrides generic 401 handler", () => {
	let originalCalled = 0;
	const loginApi = {
		login_handlers: {
			401: function () {
				originalCalled += 1;
			},
		},
	};

	const container = createElement("div");

	api.wrapLoginHandlers(loginApi, {
		locale: "en",
		container,
		loginButtonLabel: "Login",
	});

	loginApi.login_handlers[401]({
		responseJSON: {
			nozom_login_error: "ONLINE_USER_LIMIT_REACHED",
		},
	});

	assert.strictEqual(originalCalled, 0);
	assert.strictEqual(container.hidden, false);
	assert.ok(findLink(container));
});

console.log(`\n${passed} tests passed`);
