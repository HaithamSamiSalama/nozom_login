import base64
import hashlib
import hmac
import json
import time

import frappe
from frappe import _
from frappe.auth import LoginManager


TOKEN_MAX_FUTURE_SECONDS = 5 * 60
TOKEN_CLOCK_TOLERANCE_SECONDS = 30


def _decode_base64url(value: str) -> bytes:
	padding = "=" * (-len(value) % 4)

	return base64.urlsafe_b64decode(
		(value + padding).encode("ascii")
	)


def _invalid_token():
	frappe.respond_as_web_page(
		_("Not Permitted"),
		_("The setup link is invalid, expired, or has already been used."),
		http_status_code=403,
		indicator_color="red",
	)


@frappe.whitelist(
	allow_guest=True,
	methods=["GET"],
)
def login_to_setup(token: str):
	if not token or "." not in token:
		return _invalid_token()

	secret = frappe.conf.get(
		"nozom_sso_secret"
	)

	if not secret:
		frappe.log_error(
			title="NOZOM Setup Login Error",
			message="nozom_sso_secret is missing from site configuration.",
		)

		return _invalid_token()

	try:
		encoded_payload, supplied_signature = token.split(
			".",
			1,
		)

		expected_signature = hmac.new(
			secret.encode("utf-8"),
			encoded_payload.encode("ascii"),
			hashlib.sha256,
		).hexdigest()

		if not hmac.compare_digest(
			expected_signature,
			supplied_signature,
		):
			return _invalid_token()

		payload = json.loads(
			_decode_base64url(
				encoded_payload
			).decode("utf-8")
		)

		site = str(
			payload.get("site") or ""
		)

		nonce = str(
			payload.get("nonce") or ""
		)

		expires_at = int(
			payload.get("exp") or 0
		)

		issued_at = int(
			payload.get("iat") or 0
		)

	except (
		ValueError,
		TypeError,
		json.JSONDecodeError,
		UnicodeDecodeError,
	):
		return _invalid_token()

	now = int(time.time())

	if site != frappe.local.site:
		return _invalid_token()

	if not nonce or len(nonce) < 16:
		return _invalid_token()

	if expires_at < now:
		return _invalid_token()

	if issued_at > now + TOKEN_CLOCK_TOLERANCE_SECONDS:
		return _invalid_token()

	if (
		expires_at - now >
		TOKEN_MAX_FUTURE_SECONDS +
		TOKEN_CLOCK_TOLERANCE_SECONDS
	):
		return _invalid_token()

	cache_key = (
		f"nozom_setup_token:{nonce}"
	)

	if frappe.cache.get_value(cache_key):
		return _invalid_token()

	remaining_seconds = max(
		1,
		expires_at - now,
	)

	frappe.cache.set_value(
		cache_key,
		"used",
		expires_in_sec=remaining_seconds,
	)

	frappe.local.login_manager = LoginManager()
	frappe.local.login_manager.login_as(
		"Administrator"
	)

	frappe.local.response["type"] = "redirect"

	if frappe.is_setup_complete():
		frappe.local.response["location"] = (
			"/desk"
		)
	else:
		frappe.local.response["location"] = (
			"/app/setup-wizard"
		)


def _verify_nozom_request(
	timestamp: str,
	signature: str,
):
	secret = frappe.conf.get(
		"nozom_sso_secret"
	)

	if not secret:
		return False

	try:
		request_timestamp = int(
			timestamp
		)
	except (
		TypeError,
		ValueError,
	):
		return False

	now = int(time.time())

	if abs(now - request_timestamp) > 60:
		return False

	message = (
		f"{frappe.local.site}:{request_timestamp}"
	)

	expected_signature = hmac.new(
		secret.encode("utf-8"),
		message.encode("utf-8"),
		hashlib.sha256,
	).hexdigest()

	return hmac.compare_digest(
		expected_signature,
		signature or "",
	)


@frappe.whitelist(
	allow_guest=True,
	methods=["GET"],
)
def get_setup_status(
	timestamp: str,
	signature: str,
):
	if not _verify_nozom_request(
		timestamp,
		signature,
	):
		frappe.throw(
			_("Not permitted"),
			frappe.PermissionError,
		)

	return {
		"setup_complete":
			bool(
				frappe.is_setup_complete()
			),
		"site":
			frappe.local.site,
	}


@frappe.whitelist(
	allow_guest=True,
	methods=["GET"],
)
def get_session_monitoring(
	timestamp: str,
	signature: str,
):
	"""
	Trusted Cloud → site read-only monitoring.

	Authenticated with the same HMAC used by get_setup_status
	(nozom_sso_secret / site:timestamp). Never expose SIDs or secrets.
	"""

	if not _verify_nozom_request(
		timestamp,
		signature,
	):
		frappe.throw(
			_("Not permitted"),
			frappe.PermissionError,
		)

	from nozom_core.sessions.monitoring import (
		build_session_monitoring_payload,
	)

	return build_session_monitoring_payload()


def _resolve_chart_of_accounts(country: str, supplied: str | None):
	if supplied and str(supplied).strip():
		return str(supplied).strip()

	try:
		from erpnext.accounts.doctype.account.chart_of_accounts.chart_of_accounts import (
			get_charts_for_country,
		)

		charts = get_charts_for_country(country) or []
		if charts:
			return charts[0]
	except Exception:
		frappe.log_error(
			title="NOZOM Setup Chart Lookup",
			message=frappe.get_traceback(),
		)

	return ""


@frappe.whitelist(
	allow_guest=True,
	methods=["POST"],
)
def complete_company_setup(
	timestamp: str | None = None,
	signature: str | None = None,
	setup: dict | str | None = None,
):
	"""
	Trusted Cloud → site ERPNext setup completion.

	Runs the official Frappe/ERPNext setup wizard path (idempotent).
	Does not hide the wizard — it completes it through setup_complete.
	Passwords must arrive in the JSON body only; never log them.
	"""

	form = frappe.local.form_dict or frappe._dict()
	timestamp = timestamp or form.get("timestamp")
	signature = signature or form.get("signature")
	setup = setup if setup is not None else form.get("setup")

	if not _verify_nozom_request(
		str(timestamp or ""),
		str(signature or ""),
	):
		frappe.throw(
			_("Not permitted"),
			frappe.PermissionError,
		)

	if frappe.is_setup_complete():
		return {
			"status": "ok",
			"setup_complete": True,
			"already_complete": True,
			"site": frappe.local.site,
		}

	if isinstance(setup, str):
		try:
			setup = json.loads(setup)
		except json.JSONDecodeError:
			frappe.throw(_("Invalid setup payload"))

	if not isinstance(setup, dict):
		frappe.throw(_("Invalid setup payload"))

	args = frappe._dict(setup)

	required = [
		"country",
		"currency",
		"timezone",
		"company_name",
		"company_abbr",
		"full_name",
		"email",
		"password",
		"fy_start_date",
		"fy_end_date",
	]

	missing = [key for key in required if not args.get(key)]
	if missing:
		frappe.throw(
			_("Missing setup fields: {0}").format(
				", ".join(missing)
			)
		)

	args.chart_of_accounts = _resolve_chart_of_accounts(
		args.country,
		args.get("chart_of_accounts"),
	)

	# Never create a second Administrator. System Manager user is created
	# by frappe setup_complete / create_or_update_user from email+password.
	from frappe.desk.page.setup_wizard.setup_wizard import (
		setup_complete as frappe_setup_complete,
	)

	# Mute welcome mails; Cloud owns customer messaging.
	_mute_emails, frappe.flags.mute_emails = frappe.flags.mute_emails, True

	try:
		result = frappe_setup_complete(args)
	finally:
		frappe.flags.mute_emails = _mute_emails
		# Best-effort wipe of password from form_dict after use.
		if hasattr(frappe.local, "form_dict") and frappe.local.form_dict:
			if isinstance(frappe.local.form_dict.get("setup"), dict):
				frappe.local.form_dict.setup.pop("password", None)
			frappe.local.form_dict.pop("password", None)

	frappe.db.commit()

	return {
		"status": (result or {}).get("status") if isinstance(result, dict) else "ok",
		"setup_complete": bool(frappe.is_setup_complete()),
		"already_complete": False,
		"site": frappe.local.site,
	}
