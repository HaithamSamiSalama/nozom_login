/**
 * NOZOM login handler for post-auth online-user-limit errors.
 *
 * Safe rendering only: textContent + explicitly created <a>.
 * Does not inject backend HTML.
 */
(function (global) {
	"use strict";

	var ERROR_CODE = "ONLINE_USER_LIMIT_REACHED";

	var PAYMENT_URLS = {
		ar: "https://www.nozom.cloud/ar/dashboard/payments/new",
		en: "https://www.nozom.cloud/en/dashboard/payments/new",
	};

	var MESSAGES = {
		ar: {
			line1:
				"تم الوصول إلى الحد الأقصى للمستخدمين المتصلين حاليًا حسب اشتراكك.",
			beforeLink: "لترقية اشتراكك وزيادة عدد المستخدمين، ",
			linkText: "اضغط هنا",
			afterLink: ".",
		},
		en: {
			line1:
				"The maximum number of currently online users allowed by your subscription has been reached.",
			beforeLink:
				"To upgrade your subscription and increase the user limit, ",
			linkText: "click here",
			afterLink: ".",
		},
	};

	function normalizeLocale(locale) {
		var value = String(locale || "en").toLowerCase();
		return value.indexOf("ar") === 0 ? "ar" : "en";
	}

	function getPaymentUrl(locale) {
		return PAYMENT_URLS[normalizeLocale(locale)];
	}

	function getMessageParts(locale) {
		return MESSAGES[normalizeLocale(locale)];
	}

	function isOnlineUserLimitError(data) {
		return Boolean(
			data &&
				data.nozom_login_error === ERROR_CODE
		);
	}

	function parseResponseData(xhr) {
		if (!xhr) {
			return null;
		}

		if (xhr.responseJSON) {
			return xhr.responseJSON;
		}

		if (!xhr.responseText) {
			return null;
		}

		try {
			return JSON.parse(xhr.responseText);
		} catch (error) {
			return null;
		}
	}

	function clearMessage(container) {
		if (!container) {
			return;
		}

		while (container.firstChild) {
			container.removeChild(container.firstChild);
		}

		container.hidden = true;
	}

	function renderMessage(container, locale) {
		if (!container) {
			return null;
		}

		clearMessage(container);

		var parts = getMessageParts(locale);
		var paymentUrl = getPaymentUrl(locale);

		var line1 = document.createElement("p");
		line1.className = "nozom-online-user-limit-line";
		line1.textContent = parts.line1;
		container.appendChild(line1);

		var line2 = document.createElement("p");
		line2.className = "nozom-online-user-limit-line";
		line2.appendChild(
			document.createTextNode(parts.beforeLink)
		);

		var link = document.createElement("a");
		link.className = "nozom-online-user-limit-link";
		link.href = paymentUrl;
		link.target = "_blank";
		link.rel = "noopener noreferrer";
		link.textContent = parts.linkText;
		line2.appendChild(link);

		line2.appendChild(
			document.createTextNode(parts.afterLink)
		);
		container.appendChild(line2);

		container.hidden = false;

		return {
			locale: normalizeLocale(locale),
			paymentUrl: paymentUrl,
			linkText: parts.linkText,
			line1: parts.line1,
		};
	}

	function showLimitError(options) {
		var opts = options || {};
		var locale = normalizeLocale(opts.locale);
		var container =
			opts.container ||
			document.getElementById(
				"nozom-online-user-limit-message"
			);

		renderMessage(container, locale);

		var card = document.querySelector(
			".for-login .login-content.page-card"
		);

		if (card) {
			card.classList.add("invalid-login");
			global.setTimeout(function () {
				card.classList.remove("invalid-login");
			}, 500);
		}

		var body = document.querySelector(
			".for-login .page-card-body"
		);

		if (body) {
			body.classList.add("invalid");
		}

		var button =
			document.querySelector(".for-login .btn-login") ||
			document.querySelector(
				"section.for-login .btn-primary"
			);

		if (button && opts.loginButtonLabel) {
			button.textContent = opts.loginButtonLabel;
		}

		var password = document.getElementById(
			"login_password"
		);

		if (password && password.focus) {
			password.focus();
		}

		return {
			locale: locale,
			paymentUrl: getPaymentUrl(locale),
			container: container,
		};
	}

	function wrapLoginHandlers(loginApi, options) {
		if (
			!loginApi ||
			!loginApi.login_handlers ||
			typeof loginApi.login_handlers[401] !== "function"
		) {
			return false;
		}

		if (loginApi.login_handlers.__nozomOnlineUserLimitWrapped) {
			return true;
		}

		var original401 = loginApi.login_handlers[401];
		var opts = options || {};

		loginApi.login_handlers[401] = function (xhr) {
			var data = parseResponseData(xhr);

			if (isOnlineUserLimitError(data)) {
				showLimitError(opts);
				return;
			}

			clearMessage(
				opts.container ||
					document.getElementById(
						"nozom-online-user-limit-message"
					)
			);

			return original401.apply(this, arguments);
		};

		loginApi.login_handlers.__nozomOnlineUserLimitWrapped = true;
		return true;
	}

	var api = {
		ERROR_CODE: ERROR_CODE,
		PAYMENT_URLS: PAYMENT_URLS,
		MESSAGES: MESSAGES,
		normalizeLocale: normalizeLocale,
		getPaymentUrl: getPaymentUrl,
		getMessageParts: getMessageParts,
		isOnlineUserLimitError: isOnlineUserLimitError,
		parseResponseData: parseResponseData,
		clearMessage: clearMessage,
		renderMessage: renderMessage,
		showLimitError: showLimitError,
		wrapLoginHandlers: wrapLoginHandlers,
	};

	global.NozomOnlineUserLimitLogin = api;
})(typeof window !== "undefined" ? window : globalThis);
