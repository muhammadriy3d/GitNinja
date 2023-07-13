import PyInstaller.__main__ as pyi

program_dir = 'GitNinja/git_ninja.py'

# Set the configuration options
options = [
    '--name=GitNinja',                                      # Name of the executable
    '--onefile',                                            # Create a single executable file
    '--windowed',                                           # Run the script without showing a console window
    '--icon=icon.ico',                                      # Optional: Path to the icon file for the executable
    '--version-file=version.txt',                              # Optional: Set the author name
    '--add-data=license.txt:.',                             # Optional: Add a license file
    '--add-data=README.md:.',                               # Optional: Add a readme file
    program_dir                                             # Path to your Python script
]

# Build the executable
pyi.run(options)
