import datetime
import hashlib
import hmac
import json
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import frappe


NOZOM_STATUS_URL = (
	"https://nozom.cloud/"
	"api/internal/subscriptions/site-status"
)

CACHE_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 6


def _empty_status():
	return {
		"provider": "unknown",
		"status": "UNKNOWN",
		"expiry_date": None,
		"remaining_days": None,
		"blocked": False,
		"message": None,
		"source_available": False,
	}


def _parse_iso_date(value):
	if not value:
		return None

	try:
		return datetime.date.fromisoformat(
			str(value)[:10]
		)
	except (
		TypeError,
		ValueError,
	):
		return None


def _format_legacy_date(value):
	if not value:
		return None

	if isinstance(
		value,
		datetime.datetime,
	):
		value = value.date()

	if isinstance(
		value,
		datetime.date,
	):
		return value.strftime(
			"%d/%m/%Y"
		)

	return str(value)


def get_legacy_file_status():
	result = _empty_status()

	result.update({
		"provider": "legacy_file",
		"status": "ACTIVE",
		"source_available": True,
	})

	try:
		data_txt_path = frappe.get_site_path(
			"data.txt"
		)

		import os

		if not os.path.exists(
			data_txt_path
		):
			return result

		with open(
			data_txt_path,
			"r",
			encoding="utf-8",
		) as file:
			expiry_date_str = (
				file.read().strip()
			)

		if not expiry_date_str:
			return result

		expiry_date = datetime.datetime.strptime(
			expiry_date_str,
			"%d/%m/%Y",
		).date()

		today = datetime.date.today()

		remaining_days = (
			expiry_date - today
		).days

		result.update({
			"expiry_date":
				expiry_date_str,

			"remaining_days":
				remaining_days,

			"status":
				"EXPIRED"
				if remaining_days < 0
				else "ACTIVE",

			"blocked":
				remaining_days < 0,
		})

		return result

	except Exception:
		frappe.log_error(
			title=(
				"Legacy Subscription "
				"Check Error"
			),
			message=frappe.get_traceback(),
		)

		return result


def _cache_key():
	return (
		"nozom_subscription_status:"
		f"{frappe.local.site}"
	)


def _read_cached_status():
	value = frappe.cache.get_value(
		_cache_key()
	)

	if not value:
		return None

	if isinstance(value, dict):
		return value

	try:
		return json.loads(value)
	except (
		TypeError,
		json.JSONDecodeError,
	):
		return None


def _save_cached_status(value):
	frappe.cache.set_value(
		_cache_key(),
		json.dumps(value),
		expires_in_sec=CACHE_SECONDS,
	)


def get_nozom_status():
	result = _empty_status()

	result["provider"] = "nozom"

	secret = frappe.conf.get(
		"nozom_sso_secret"
	)

	if not secret:
		frappe.log_error(
			title=(
				"NOZOM Subscription "
				"Configuration Error"
			),
			message=(
				"nozom_sso_secret "
				"is missing."
			),
		)

		cached = _read_cached_status()

		return cached or result

	site = frappe.local.site
	timestamp = str(int(time.time()))

	message = (
		f"{site}:{timestamp}"
	)

	signature = hmac.new(
		secret.encode("utf-8"),
		message.encode("utf-8"),
		hashlib.sha256,
	).hexdigest()

	query = urlencode({
		"site": site,
		"timestamp": timestamp,
		"signature": signature,
	})

	request = Request(
		f"{NOZOM_STATUS_URL}?{query}",
		headers={
			"Accept":
				"application/json",

			"User-Agent":
				"NOZOM-Login/1.0",
		},
		method="GET",
	)

	try:
		with urlopen(
			request,
			timeout=REQUEST_TIMEOUT_SECONDS,
		) as response:
			payload = json.loads(
				response.read().decode(
					"utf-8"
				)
			)

		expiry_date = _parse_iso_date(
			payload.get("expiryDate")
		)

		today = datetime.date.today()

		remaining_days = (
			(expiry_date - today).days
			if expiry_date
			else None
		)

		raw_status = (
			payload.get("status")
			or "UNKNOWN"
		)
		raw_blocked = bool(
			payload.get(
				"blocked",
				False,
			)
		)

		status = raw_status
		blocked = raw_blocked

		# The actual expiry date is authoritative for expiry.
		# This also handles an admin extension where the central
		# stored status has not yet changed from EXPIRED.
		if expiry_date:
			if remaining_days is not None and remaining_days < 0:
				status = "EXPIRED"
				blocked = True
			elif raw_status == "EXPIRED":
				status = "ACTIVE"
				blocked = False

		result.update({
			"status": status,

			"expiry_date":
				_format_legacy_date(
					expiry_date
				),

			"remaining_days":
				remaining_days,

			"blocked": blocked,

			"message":
				payload.get("message"),

			"source_available":
				True,
		})

		_save_cached_status(result)

		return result

	except Exception:
		frappe.log_error(
			title=(
				"NOZOM Subscription "
				"Check Error"
			),
			message=frappe.get_traceback(),
		)

		cached = _read_cached_status()

		if cached:
			cached["source_available"] = False
			return cached

		# Fail open when the central API is
		# temporarily unavailable and there
		# is no cached result.
		result.update({
			"status": "UNAVAILABLE",
			"blocked": False,
			"source_available": False,
		})

		return result


DEV_SECRET_HASH = "6860c524d83f0d87fc5a424a4bab585d691448deec6b5fac33034ec2aa0bffa3"


def _get_local_development_status():
	if not frappe.conf.get("developer_mode"):
		return None

	try:
		data_txt_path = frappe.get_site_path("data.txt")

		import os

		if not os.path.exists(data_txt_path):
			return None

		with open(
			data_txt_path,
			"r",
			encoding="utf-8",
		) as file:
			secret = file.read().strip()

		if not secret:
			return None

		secret_hash = hashlib.sha256(
			secret.encode("utf-8")
		).hexdigest()

		if not hmac.compare_digest(
			secret_hash,
			DEV_SECRET_HASH,
		):
			return None

		return {
			"provider": "local_development",
			"status": "ACTIVE",
			"expiry_date": None,
			"remaining_days": None,
			"blocked": False,
			"source_available": True,
			"message": (
				"Development environment - "
				"subscription validation is disabled."
			),
		}

	except Exception:
		frappe.log_error(
			title="Local Development Check Error",
			message=frappe.get_traceback(),
		)
		return None


def _core_is_available():
	try:
		return "nozom_core" in frappe.get_installed_apps()
	except Exception:
		return False


def get_subscription_status():
	"""
	Compatibility adapter.

	Managed NOZOM systems use nozom_core as the subscription
	source of truth. Sites without nozom_core preserve the
	previous nozom_login subscription behaviour.
	"""
	if _core_is_available():
		from nozom_core.entitlements.subscription import (
			get_subscription_status as get_core_subscription_status,
		)

		return get_core_subscription_status()

	development_status = _get_local_development_status()

	if development_status:
		return development_status

	return get_nozom_status()


def clear_subscription_cache():
	"""Clear the appropriate subscription cache."""
	if _core_is_available():
		from nozom_core.entitlements.subscription import (
			clear_subscription_cache as clear_core_subscription_cache,
		)

		clear_core_subscription_cache()
		return

	frappe.cache.delete_value(_cache_key())
