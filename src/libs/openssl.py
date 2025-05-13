from .lib_template import *
import string

class OpenSSLSeeker(Seeker):
    """Seeker (Identifier) for the OpenSSL open source library."""

    # Library Name
    NAME = "OpenSSL"
    # version string marker
    VERSION_STRING = " part of OpenSSL "
    CELLAR_STRING = "/Cellar/openssl"  # e.g. /usr/local/Cellar/openssl@3/3.5.0/lib

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        key_string = self.VERSION_STRING
        cellar_string = self.CELLAR_STRING
        ids = ["SHA1", "SHA-256", "SHA-512", "SSLv3", "TLSv1", "ASN.1", "EVP", "RAND", "RSA", "Big Number"]

        # Now search
        self._version_strings = []
        seen_copyrights = set()
        match_counter = 0
        for bin_str in self._all_strings:
            # we have a match
            s_bin_str = str(bin_str)
            if key_string in s_bin_str:
                copyright_string = s_bin_str
                # check for a supporting key word id
                if len([x for x in ids if x in copyright_string]) != 0:
                    # check for a duplicate inside the same library
                    chopped_copyright_string = copyright_string[copyright_string.find(key_string):]
                    if match_counter >= 1 and chopped_copyright_string in seen_copyrights:
                        continue
                    # valid match
                    logger.debug(f"Located a copyright string of {self.NAME} in address 0x{bin_str.ea:x}")
                    match_counter += 1
                    seen_copyrights.add(chopped_copyright_string)
                    # save the string for later
                    self._version_strings.append(chopped_copyright_string)
            if cellar_string in s_bin_str:
                if len(s_bin_str) < len(cellar_string) + 4:
                    # false match
                    continue
                full_string = s_bin_str
                n = full_string.find(cellar_string)
                left_slash = full_string.find("/", n + len(cellar_string))
                if left_slash > 0:
                    right_slash = full_string.find("/", left_slash + 1)
                    if right_slash > 0:
                        ver_string = full_string[left_slash + 1:right_slash]
                    else:
                        ver_string = full_string[left_slash + 1:]
                    logger.debug(f"Located a Cellar string of {self.NAME} in address 0x{bin_str.ea:x}")
                    if match_counter >= 1 and ver_string in seen_copyrights:
                        # ignore duplicate version string
                        continue
                    match_counter += 1
                    seen_copyrights.add(ver_string)
                    self._version_strings.append(ver_string)

        # return the result
        return len(self._version_strings)

    # Overridden base function
    def identifyVersions(self, logger):
        """Identify the version(s) of the library (assuming it was already found).

        Assumptions:
            1. searchLib() was called before calling identifyVersions()
            2. The call to searchLib() returned a number > 0

        Args:
            logger (logger): elementals logger instance

        Return Value:
            list of Textual ID(s) of the library's version(s)
        """
        results = []
        # extract the version from the copyright string
        for work_str in self._version_strings:
            if work_str.find(self.NAME) >= 0:
                copyrights = self.extractVersion(work_str, start_index=work_str.find(self.NAME) + len(self.NAME) + 1, legal_chars=string.digits + string.ascii_lowercase + '.')
                if copyrights:
                    results.append(copyrights)
            else:
                cellars = self.extractVersion(work_str, start_index=0, legal_chars=string.digits + string.ascii_lowercase + '.')
                if cellars:
                    results.append(cellars)
        # return the result
        return results


# Register our class
OpenSSLSeeker.register(OpenSSLSeeker.NAME, OpenSSLSeeker)
