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


def _parse_setup_payload(setup):
	if isinstance(setup, str):
		try:
			setup = json.loads(setup)
		except json.JSONDecodeError:
			frappe.throw(_("Invalid setup payload"))

	if not isinstance(setup, dict):
		frappe.throw(_("Invalid setup payload"))

	return frappe._dict(setup)


def _wipe_setup_password_from_form():
	# Best-effort wipe of password from form_dict after use.
	if hasattr(frappe.local, "form_dict") and frappe.local.form_dict:
		if isinstance(frappe.local.form_dict.get("setup"), dict):
			frappe.local.form_dict.setup.pop("password", None)
		frappe.local.form_dict.pop("password", None)


def _ensure_system_manager_user(args):
	"""
	Create or update the customer System Manager from Cloud credentials.

	Never touches the protected technical Administrator account.
	Safe to call when setup is already complete.

	Runs under a trusted HMAC-verified Cloud request (often as Guest), so
	user mutations must ignore session permissions.
	"""
	from frappe.utils.password import update_password

	email = (args.get("email") or "").strip().lower()
	full_name = (args.get("full_name") or "").strip() or email.split("@")[0]
	password = args.get("password")

	if not email or not password:
		frappe.throw(_("Missing setup fields: email, password"))

	if email in frappe.STANDARD_USERS or email.lower() == "administrator":
		frappe.throw(_("Invalid setup fields: email"))

	first_name, last_name = full_name, ""
	if " " in full_name:
		first_name, last_name = full_name.split(" ", 1)

	if frappe.db.exists("User", email):
		user = frappe.get_doc("User", email)
		changed = False
		if user.first_name != first_name or user.last_name != last_name:
			user.first_name = first_name
			user.last_name = last_name
			changed = True
		if not user.enabled:
			user.enabled = 1
			changed = True
		if changed:
			user.save(ignore_permissions=True)
	else:
		user = frappe.new_doc("User")
		user.update(
			{
				"email": email,
				"first_name": first_name,
				"last_name": last_name,
				"send_welcome_email": 0,
				"user_type": "System User",
			}
		)
		user.flags.no_welcome_mail = True
		user.insert(ignore_permissions=True)

	roles = set(frappe.get_roles(email))
	if "System Manager" not in roles:
		user = frappe.get_doc("User", email)
		user.add_roles("System Manager")

	update_password(email, password)
	frappe.db.commit()

	return email


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

	If setup is already complete, still syncs the customer System Manager
	email/password so login matches the Cloud onboarding form.
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

	args = _parse_setup_payload(setup)

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

	# Mute welcome mails; Cloud owns customer messaging.
	_mute_emails, frappe.flags.mute_emails = frappe.flags.mute_emails, True
	# HMAC-verified Cloud → site call typically arrives as Guest. Elevate only
	# for the duration of trusted setup so official wizard stages and owner
	# sync can create Company / User / Fiscal Year documents.
	previous_user = frappe.session.user
	result = None
	admin_email = None

	try:
		frappe.set_user("Administrator")

		if frappe.is_setup_complete():
			admin_email = _ensure_system_manager_user(args)
			return {
				"status": "ok",
				"setup_complete": True,
				"already_complete": True,
				"admin_synced": True,
				"admin_email": admin_email,
				"site": frappe.local.site,
			}

		args.chart_of_accounts = _resolve_chart_of_accounts(
			args.country,
			args.get("chart_of_accounts"),
		)

		# Never create a second Administrator. System Manager user is created
		# by frappe setup_complete / create_or_update_user from email+password.
		from frappe.desk.page.setup_wizard.setup_wizard import (
			setup_complete as frappe_setup_complete,
		)

		result = frappe_setup_complete(args)

		# Ensure credentials stick even if wizard stages skipped user creation.
		admin_email = _ensure_system_manager_user(args)
	finally:
		frappe.flags.mute_emails = _mute_emails
		try:
			frappe.set_user(previous_user)
		except Exception:
			frappe.set_user("Guest")
		_wipe_setup_password_from_form()

	frappe.db.commit()

	return {
		"status": (result or {}).get("status") if isinstance(result, dict) else "ok",
		"setup_complete": bool(frappe.is_setup_complete()),
		"already_complete": False,
		"admin_synced": True,
		"admin_email": admin_email,
		"site": frappe.local.site,
	}


@frappe.whitelist(
	allow_guest=True,
	methods=["GET"],
)
def login_to_company(token: str):
	"""
	Trusted Cloud → passwordless first entry for the company System Manager.

	Short-lived, single-use HMAC token. Never accepts Administrator.
	Only redirects to /desk when official setup is complete; otherwise
	returns an error page (Cloud owns recovery UI).
	"""
	if not token or "." not in token:
		return _invalid_token()

	secret = frappe.conf.get("nozom_sso_secret")
	if not secret:
		frappe.log_error(
			title="NOZOM Company Login Error",
			message="nozom_sso_secret is missing from site configuration.",
		)
		return _invalid_token()

	try:
		encoded_payload, supplied_signature = token.split(".", 1)
		expected_signature = hmac.new(
			secret.encode("utf-8"),
			encoded_payload.encode("ascii"),
			hashlib.sha256,
		).hexdigest()

		if not hmac.compare_digest(expected_signature, supplied_signature):
			return _invalid_token()

		payload = json.loads(_decode_base64url(encoded_payload).decode("utf-8"))
		site = str(payload.get("site") or "")
		email = str(payload.get("email") or "").strip().lower()
		purpose = str(payload.get("purpose") or "")
		nonce = str(payload.get("nonce") or "")
		expires_at = int(payload.get("exp") or 0)
		issued_at = int(payload.get("iat") or 0)
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

	if purpose != "company_entry":
		return _invalid_token()

	if not email or email in ("administrator", "guest"):
		return _invalid_token()

	if not nonce or len(nonce) < 16:
		return _invalid_token()

	if expires_at < now:
		return _invalid_token()

	if issued_at > now + TOKEN_CLOCK_TOLERANCE_SECONDS:
		return _invalid_token()

	if expires_at - now > TOKEN_MAX_FUTURE_SECONDS + TOKEN_CLOCK_TOLERANCE_SECONDS:
		return _invalid_token()

	if not frappe.is_setup_complete():
		frappe.respond_as_web_page(
			_("Company Setup Incomplete"),
			_("Your company system is still being prepared. Please return to NOZOM Cloud."),
			http_status_code=409,
			indicator_color="orange",
		)
		return

	if not frappe.db.exists("User", email):
		return _invalid_token()

	user_enabled = frappe.db.get_value("User", email, "enabled")
	if not cint_safe(user_enabled):
		return _invalid_token()

	# Company entry is only for the customer System Manager identity — never
	# elevate arbitrary site users even if a token somehow names them.
	roles = set(frappe.get_roles(email))
	if "System Manager" not in roles:
		return _invalid_token()

	cache_key = f"nozom_company_entry_token:{nonce}"
	if frappe.cache.get_value(cache_key):
		return _invalid_token()

	remaining_seconds = max(1, expires_at - now)
	frappe.cache.set_value(cache_key, "used", expires_in_sec=remaining_seconds)

	frappe.local.login_manager = LoginManager()
	frappe.local.login_manager.login_as(email)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = "/desk"


def cint_safe(value):
	try:
		from frappe.utils import cint

		return cint(value)
	except Exception:
		return 1 if value else 0
