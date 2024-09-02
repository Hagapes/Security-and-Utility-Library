import requests as rq
import base64
import re

class START:
    def __init__(self) -> None:
        """
        Initializes the START class.
        """
        pass

    def email_validate(self, email: str) -> bool:
        """
        Validates if an email address is valid.

        Args:
            email (str): The email address to be validated.

        Returns:
            bool: True if the email is valid, False otherwise.
        """
        regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.fullmatch(regex, email) is not None

    def password_strong(self, password: str, min_len=4, max_len=32, alphanumeric=True, special_chars=True, capital_char=True) -> bool:
        """
        Checks if a password is strong based on specific criteria.

        Args:
            password (str): The password to be checked.
            min_len (int, optional): The minimum length of the password. Default is 4.
            max_len (int, optional): The maximum length of the password. Default is 32.
            alphanumeric (bool, optional): Whether the password must contain alphanumeric characters. Default is True.
            special_chars (bool, optional): Whether the password must contain special characters. Default is True.
            capital_char (bool, optional): Whether the password must contain uppercase characters. Default is True.

        Returns:
            bool: True if the password meets the criteria for being strong, False otherwise.
        """
        pattern = rf'^.{{{min_len},{max_len}}}$'
        
        if alphanumeric:
            pattern = rf'(?=.*[a-zA-Z])(?=.*\d){pattern}'
        
        if special_chars:
            pattern = rf'(?=.*[\W_]){pattern}'
        
        if capital_char:
            pattern = rf'(?=.*[A-Z]){pattern}'

        return re.fullmatch(pattern, password) is not None

    def email_breach_check(self, email: str) -> bool:
        """
        Checks if an email address has been detected in a data breach.

        Args:
            email (str): The email address to be checked.

        Returns:
            bool: True if the email was found in a data breach, False otherwise.
        """
        username = email.split('@')[0]
        try:
            response = rq.get(f'https://api.proxynova.com/comb?query={username}&start=0&limit=15')
            response.raise_for_status()
            jsn = response.json().get("lines")

            if jsn:
                for i in jsn:
                    if i.split(':')[0].lower() == email:
                        return True
        except rq.RequestException as e:
            print(f"Request error: {e}")
        return False

    def ip_country(self, ip: str) -> str:
        """
        Retrieves the country code for a given IP address.

        Args:
            ip (str): The IP address to be checked.

        Returns:
            str: The country code if the IP is valid, None otherwise.
        """
        try:
            response = rq.get(f'https://aether.epias.ltd/ip2country/{ip}')
            response.raise_for_status()
            return response.text
        except rq.RequestException as e:
            print(f"Request error: {e}")
            return None

    def ip_validate(self, ip: str) -> bool:
        """
        Validates if an IP address is real.

        Args:
            ip (str): The IP address to be validated.

        Returns:
            bool: True if the IP address is valid, False otherwise.
        """
        try:
            response = rq.get(f'https://aether.epias.ltd/ip2country/{ip}')
            response.raise_for_status()
            return True
        except rq.RequestException:
            return False

    def ip_get(self) -> str:
        """
        Retrieves the public IP address of the current device.

        Returns:
            str: The public IP address if the request is successful.
        """
        try:
            response = rq.get("https://api.ipify.org/")
            response.raise_for_status()
            return response.text
        except rq.RequestException as e:
            print(f"Request error: {e}")
            return None

    def base64_encode(self, text: str) -> str:
        """
        Encodes a string to Base64 format.

        Args:
            text (str): The string to be encoded.

        Returns:
            str: The Base64 encoded string.
        """
        string_bytes = text.encode('utf-8')
        base64_bytes = base64.b64encode(string_bytes)
        base64_string = base64_bytes.decode('utf-8')
        return base64_string

    def base64_decode(self, text: str) -> str:
        """
        Decodes a Base64 encoded string.

        Args:
            text (str): The Base64 encoded string to be decoded.

        Returns:
            str: The decoded string, or None if decoding fails.
        """
        try:
            base64_bytes = text.encode('utf-8')
            string_bytes = base64.b64decode(base64_bytes)
            return string_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            print(f"Base64 decoding error: {e}")
            return None
