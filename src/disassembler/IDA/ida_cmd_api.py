from disassembler.disas_api import DisasCMD
from disassembler.factory   import registerDisassemblerCMD
import os

class IdaCMD(DisasCMD):
    """DisasCMD implementation for the IDA disassembler."""

    # Overridden base function
    @staticmethod
    def identify(path):
        """Check if the given command-line path refers to this disassembler.

        Args:
            path (str): command-line path to some disassembler (maybe for us)

        Return Value:
            True iff the command-line path refers to our program
        """
        return os.path.split(path)[-1].split(".")[0].lower().startswith("ida")

    # Overridden base function
    @staticmethod
    def name():
        """Return the program's name (used mainly for bug fixes in our code...).

        Return Value:
            String name of the disassembler program
        """
        return "IDA"

    # Overridden base function
    def createDatabase(self, binary_file, is_windows, skip_present=True):
        """Create a database file for the given binary file, compiled to windows or linux as specified.

        Args:
            binary_file (path): path to the input binary (*.o / *.obj) file
            is_windows (bool): True if this is a binary that was compiled for windows (*.obj), False otherwise (*.o)

        Return Value:
            path to the created database file
        """
        suffix = ".i64" #if self._path.endswith("64") else ".idb"
        database_file = binary_file + suffix
        if skip_present and os.path.exists(database_file):
            return database_file
        # execute the program
        wait_status = os.system(f"{self._path} -A -B -o{database_file} {binary_file}")
        exit_code = os.waitstatus_to_exitcode(wait_status)
        #print(f"INFO: {self._path} exit code: {exit_code}")
        # return back the (should be) created database file path
        return database_file

    # Overridden base function
    def executeScript(self, database, script):
        """Execute the given script over the given database file that was created earlier.

        Args:
            database (path): path to a database file created by the same program
            script (path): python script to be executed once the database is loaded
        """
        os.system(f"{self._path} -A -S{script} {database}")


# Don't forget to register at the factory
registerDisassemblerCMD(IdaCMD.identify, IdaCMD)
