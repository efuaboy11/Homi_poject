# utils/paystack.py
import requests
from django.conf import settings


class Paystack:
    base_url = "https://api.paystack.co"

    @classmethod
    def initialize_payment(cls, email, amount, reference):
        url = f"{cls.base_url}/transaction/initialize"

        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        payload = {
            "email": email,
            "amount": amount,  # already in kobo
            "reference": reference,
        }

        response = requests.post(url, json=payload, headers=headers)

        # Raise error for bad HTTP responses
        if response.status_code != 200:
            raise Exception(f"Paystack HTTP Error: {response.text}")

        try:
            data = response.json()
        except ValueError:
            raise Exception("Invalid JSON response from Paystack")

        if not data.get("status"):
            raise Exception(data.get("message", "Payment initialization failed"))

        return data