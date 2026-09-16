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

CACHE_SECONDS = 15 * 60
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
				"NOZOM-loginscr/1.0",
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

		result.update({
			"status":
				payload.get(
					"status"
				) or "UNKNOWN",

			"expiry_date":
				_format_legacy_date(
					expiry_date
				),

			"remaining_days":
				remaining_days,

			"blocked":
				bool(
					payload.get(
						"blocked",
						False,
					)
				),

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


def get_subscription_status():
	provider = (
		frappe.conf.get(
			"subscription_provider"
		)
		or "legacy_file"
	)

	if provider == "nozom":
		return get_nozom_status()

	return get_legacy_file_status()
