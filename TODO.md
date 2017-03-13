# Ideas and To-Do items
 
**Bugs**: 

* No Username or path validation (They can be any utf-8 string, like a space)

**Features to add**:

* Sanction team
* Assign members to teams
* `crypt.py rollback path/to/doc` - Delete latest version(s) of document
* `crypt.py destroy path/oo/doc` - Delete all versions of document
* setup.py - Client (installs cli)
* setup.py - Server (installs django app)
* READMEs 


**Ideas**:

* Document format validation (json + yaml)
* Document key extraction (for json + yaml)
* Document key set (for json + yaml)
* `crypt.py diff path/to/doc VERSION1 VERSION2` - Show differences between two versions
* `crypt.py edit path/to/doc` - Open editor to this file, on close of editor, update document with changes (if any)
