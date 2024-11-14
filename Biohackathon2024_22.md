## STEP 1
### Set up a development instance of Galaxy

1. Clone dev branch of github repository: 
```
git clone https://github.com/galaxyproject/galaxy.git
```

2. Create virtual environment to run galaxy in order to avoid dependency issues
```
python3 -m venv .venv
```

3. Run Galaxy
```
sh run.sh
```

## STEP 2
### Access the EGA as a remote file system from Galaxy

Enable per-user credentials

1. Set up your vault password:

Inside your **galaxy/config/galaxy.yml** uncomment:

```
#vault_config_file: vault_conf.yml
```
a. create one valid Fernet key (from Galaxy's .venv) (see https://cryptography.io/en/latest/fernet):

```
python3
>from cryptography.fernet import Fernet
>key = Fernet.generate_key()
```

b. create the **galaxy/config/vault_conf.yml** file with the following content:

```
type: database
path_prefix: /galaxy
# Encryption keys must be valid fernet keys
# To generate a valid key:
#
# Use the ascii string value as a key
# For more details, see: https://cryptography.io/en/latest/fernet/#
encryption_keys:
  - <your_fernet_key_from_previous_step>
```

The vault is now usable!

2. Within the Galaxy console: configure the page under **Preferences -> Manage Information**

3. Enable remote file sources and object stores (Check this https://docs.galaxyproject.org/en/master/admin/data.html#connecting-users-and-data)

a. Uncomment remote file sources template:

```
  - #file_source_templates_config_file: file_source_templates.yml
```

b. Fill up this template with the remote connections you want in your instance. The following template shows the content of **config/file_source_templates.yml** that are needed ONLY for this project, but any template in lib/galaxy/files/templates/examples/ can be included  to this file  (this file needs to be created from scratch; no .sample file available):

```
#The path will vary depending of your development instance!
- include: ".../galaxy/lib/galaxy/files/templates/examples/generic_ssh.yml" #This is the relevant one for this one step
```

The **.../galaxy/lib/galaxy/files/templates/examples/generic_ssh.yml** should look like this:
```
- id: ssh
  version: 0
  name: An SSH Server
  description: |
    This template allows connecting to SSH servers.
  configuration:
    type: ssh
    host: "{{ variables.host }}"
    user: "{{ variables.user }}"
    path: "{{ variables.path }}"
    port: "{{ variables.port }}"
    passwd: "{{ secrets.password }}"
    writable: "{{ variables.writable }}"
  variables:
    host:
      label: SSH Host
      type: string
      help: Host of SSH Server to connect to.
    user:
      label: SSH User
      type: string
      help: |
        Username to connect with. Leave this blank to connect to the server
        anonymously (if allowed by target server).
    path:
      label: Path
      type: string
      help: |
        Leave this blank to connect to the server
        anonymously (if allowed by target server).
    writable:
      label: Writable?
      type: boolean
      help: Is this an SSH server you have permission to write to?
    port:
      label: SSH Port
      type: integer
      help: Port used to connect to the FTP server.
      default: 22
  secrets:
    password:
      label: Password
      help: |
        Password to connect to SSH server with.
```
Having the file present will activate *Manage Your Remote File Sources* in User Preferences.

Inside this you should be able to a button labelled "Create".

If you want to create an SSH connection, fill up the details to connect to your EGA Outbox. For this, you will **NEED** an EGA user, EGA password, and path direction aside of the the host direction.

![ssh form](SSH.jpg)

If done correctly, this should allow the user to download **encryptred EGA datasets** into Galaxy.

![encrypted data](encrypted.jpg)

## STEP 3
### Including transparent Crypt4gh decryption to the EGA download from the EGA outbox

In order to properly integrate SshFS into Galaxy in order to work with crypt4gh the following files will need to be modified or created:
```
lib/galaxy/files/templates/models.py
lib/galaxy/files/sources/crypt4gh.py
lib/galaxy/files/templates/examples/ega_outbox.yml # Create this file from a copy of the ../production_ftp.yml 
config/file_source_templates.yml # declare here which template yml files to use
```
First things first, modify models.py file. It should look like this:
```
from typing import (
    Any,
    Dict,
    List,
    Literal,
    Optional,
    Type,
    Union,
)

from pydantic import RootModel

from galaxy.util.config_templates import (
    ConfiguredOAuth2Sources,
    EnvironmentDict,
    expand_raw_config,
    get_oauth2_config_from,
    ImplicitConfigurationParameters,
    MarkdownContent,
    merge_implicit_parameters,
    OAuth2Configuration,
    populate_default_variables,
    SecretsDict,
    StrictModel,
    TemplateEnvironmentEntry,
    TemplateExpansion,
    TemplateSecret,
    TemplateVariable,
    TemplateVariableValueType,
    UserDetailsDict,
)

FileSourceTemplateType = Literal["ftp", "ssh", "posix", "s3fs", "azure", "onedata", "webdav", "dropbox", "googledrive", "crypt4gh_via_ssh"]


class PosixFileSourceTemplateConfiguration(StrictModel):
    type: Literal["posix"]
    root: Union[str, TemplateExpansion]
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class PosixFileSourceConfiguration(StrictModel):
    type: Literal["posix"]
    root: str
    writable: bool = False


class OAuth2TemplateConfiguration:
    oauth2_client_id: Union[str, TemplateExpansion]
    oauth2_client_secret: Union[str, TemplateExpansion]


class DropboxFileSourceTemplateConfiguration(OAuth2TemplateConfiguration, StrictModel):
    type: Literal["dropbox"]
    writable: Union[bool, TemplateExpansion] = False
    oauth2_client_id: Union[str, TemplateExpansion]
    oauth2_client_secret: Union[str, TemplateExpansion]
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class OAuth2FileSourceConfiguration:
    oauth2_access_token: str


class DropboxFileSourceConfiguration(OAuth2FileSourceConfiguration, StrictModel):
    type: Literal["dropbox"]
    writable: bool = False
    oauth2_access_token: str


class GoogleDriveFileSourceTemplateConfiguration(OAuth2TemplateConfiguration, StrictModel):
    type: Literal["googledrive"]
    writable: Union[bool, TemplateExpansion] = False
    oauth2_client_id: Union[str, TemplateExpansion]
    oauth2_client_secret: Union[str, TemplateExpansion]
    # Will default to https://www.googleapis.com/auth/drive.file, which provides
    # access to a folder specific to your Galaxy instance. Ideally we would use
    # https://www.googleapis.com/auth/drive but that would require becoming
    # Google verified - https://support.google.com/cloud/answer/13464321#ss-rs-requirements.
    # That seems like a onerous process and I don't know how it would
    # work in the context of an open source project like Galaxy, I am
    # adding the extension point here for the brave individual that would like
    # to use it but I expect it isn't practical for the typical admin.
    oauth2_scope: Optional[Union[str, TemplateExpansion]] = None
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class GoogleDriveFileSourceConfiguration(OAuth2FileSourceConfiguration, StrictModel):
    type: Literal["googledrive"]
    writable: bool = False
    oauth2_access_token: str


class S3FSFileSourceTemplateConfiguration(StrictModel):
    type: Literal["s3fs"]
    endpoint_url: Optional[Union[str, TemplateExpansion]] = None
    anon: Optional[Union[bool, TemplateExpansion]] = False
    secret: Optional[Union[str, TemplateExpansion]] = None
    key: Optional[Union[str, TemplateExpansion]] = None
    bucket: Optional[Union[str, TemplateExpansion]] = None
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class S3FSFileSourceConfiguration(StrictModel):
    type: Literal["s3fs"]
    endpoint_url: Optional[str] = None
    anon: Optional[bool] = False
    secret: Optional[str] = None
    key: Optional[str] = None
    bucket: Optional[str] = None
    writable: bool = False

class FtpFileSourceTemplateConfiguration(StrictModel):
    type: Literal["ftp"]
    host: Union[str, TemplateExpansion]
    port: Union[int, TemplateExpansion] = 21
    user: Optional[Union[str, TemplateExpansion]] = None
    passwd: Optional[Union[str, TemplateExpansion]] = None
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class FtpFileSourceConfiguration(StrictModel):
    type: Literal["ftp"]
    host: str
    port: int = 21
    user: Optional[str] = None
    passwd: Optional[str] = None
    writable: bool = False


class SshFileSourceTemplateConfiguration(StrictModel):
    type: Literal["ssh"]
    host: Union[str, TemplateExpansion]
    port: Union[int, TemplateExpansion] = 22
    user: Optional[Union[str, TemplateExpansion]] = None
    passwd: Optional[Union[str, TemplateExpansion]] = None
    path: Union[str, TemplateExpansion]
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class Crypt4ghSshFileSourceTemplateConfiguration(StrictModel):
    type: Literal["crypt4gh_via_ssh"]
    host: Union[str, TemplateExpansion]
    port: Union[int, TemplateExpansion] = 22
    user: Union[str, TemplateExpansion]
    passwd: Union[str, TemplateExpansion]
    sec_key: Union[str, TemplateExpansion]
    path: Union[str, TemplateExpansion]
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class SshFileSourceConfiguration(StrictModel):
    type: Literal["ssh"]
    host: str
    port: int = 22
    user: Optional[str] = None
    passwd: Optional[str] = None
    path: str
    writable: bool = False


class Crypt4ghSshFileSourceConfiguration(StrictModel):
    type: Literal["crypt4gh_via_ssh"]
    host: str
    port: int = 22
    user: str
    passwd: str
    sec_key: str
    path: str
    writable: bool = False


class AzureFileSourceTemplateConfiguration(StrictModel):
    type: Literal["azure"]
    account_name: Union[str, TemplateExpansion]
    container_name: Union[str, TemplateExpansion]
    account_key: Union[str, TemplateExpansion]
    writable: Union[bool, TemplateExpansion] = False
    namespace_type: Union[str, TemplateExpansion] = "hierarchical"
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class AzureFileSourceConfiguration(StrictModel):
    type: Literal["azure"]
    account_name: str
    container_name: str
    account_key: str
    namespace_type: str = "hierarchical"
    writable: bool = False


class OnedataFileSourceTemplateConfiguration(StrictModel):
    type: Literal["onedata"]
    access_token: Union[str, TemplateExpansion]
    onezone_domain: Union[str, TemplateExpansion]
    disable_tls_certificate_validation: Union[bool, TemplateExpansion] = False
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class OnedataFileSourceConfiguration(StrictModel):
    type: Literal["onedata"]
    access_token: str
    onezone_domain: str
    disable_tls_certificate_validation: bool = False
    writable: bool = False


class WebdavFileSourceTemplateConfiguration(StrictModel):
    type: Literal["webdav"]
    url: Union[str, TemplateExpansion]
    root: Union[str, TemplateExpansion]
    login: Union[str, TemplateExpansion]
    password: Union[str, TemplateExpansion]
    writable: Union[bool, TemplateExpansion] = False
    template_start: Optional[str] = None
    template_end: Optional[str] = None


class WebdavFileSourceConfiguration(StrictModel):
    type: Literal["webdav"]
    url: str
    root: str
    login: str
    password: str
    writable: bool = False

María, [11/11/2024 20:22]
FileSourceTemplateConfiguration = Union[
    PosixFileSourceTemplateConfiguration,
    S3FSFileSourceTemplateConfiguration,
    FtpFileSourceTemplateConfiguration,
    SshFileSourceTemplateConfiguration,
    AzureFileSourceTemplateConfiguration,
    OnedataFileSourceTemplateConfiguration,
    WebdavFileSourceTemplateConfiguration,
    DropboxFileSourceTemplateConfiguration,
    GoogleDriveFileSourceTemplateConfiguration,
    Crypt4ghSshFileSourceTemplateConfiguration,
]
FileSourceConfiguration = Union[
    PosixFileSourceConfiguration,
    S3FSFileSourceConfiguration,
    FtpFileSourceConfiguration,
    SshFileSourceConfiguration,
    AzureFileSourceConfiguration,
    OnedataFileSourceConfiguration,
    WebdavFileSourceConfiguration,
    DropboxFileSourceConfiguration,
    GoogleDriveFileSourceConfiguration,
    Crypt4ghSshFileSourceConfiguration,
]


class FileSourceTemplateBase(StrictModel):
    """Version of FileSourceTemplate we can send to the UI/API.

    The configuration key in the child type may have secretes
    and shouldn't be exposed over the API - at least to non-admins.
    """

    id: str
    name: Optional[str]
    description: Optional[MarkdownContent]
    # The UI should just show the most recent version but allow
    # admins to define newer versions with new parameterizations
    # and keep old versions in template catalog for backward compatibility
    # for users with existing stores of that template.
    version: int = 0
    # Like with multiple versions, allow admins to deprecate a
    # template by hiding but keep it in the catalog for backward
    # compatibility for users with existing stores of that template.
    hidden: bool = False
    variables: Optional[List[TemplateVariable]] = None
    secrets: Optional[List[TemplateSecret]] = None


class FileSourceTemplateSummary(FileSourceTemplateBase):
    type: FileSourceTemplateType


class FileSourceTemplate(FileSourceTemplateBase):
    configuration: FileSourceTemplateConfiguration
    environment: Optional[List[TemplateEnvironmentEntry]] = None

    @property
    def type(self):
        return self.configuration.type


FileSourceTemplateCatalog = RootModel[List[FileSourceTemplate]]


class FileSourceTemplateSummaries(RootModel):
    root: List[FileSourceTemplateSummary]


def template_to_configuration(
    template: FileSourceTemplate,
    variables: Dict[str, TemplateVariableValueType],
    secrets: SecretsDict,
    user_details: UserDetailsDict,
    environment: EnvironmentDict,
    implicit: Optional[ImplicitConfigurationParameters] = None,
) -> FileSourceConfiguration:
    configuration_template = template.configuration
    populate_default_variables(template.variables, variables)
    raw_config = expand_raw_config(configuration_template, variables, secrets, user_details, environment)
    merge_implicit_parameters(raw_config, implicit)
    return to_configuration_object(raw_config)


TypesToConfigurationClasses: Dict[FileSourceTemplateType, Type[FileSourceConfiguration]] = {
    "ftp": FtpFileSourceConfiguration,
    "ssh": SshFileSourceConfiguration,
    "posix": PosixFileSourceConfiguration,
    "s3fs": S3FSFileSourceConfiguration,
    "azure": AzureFileSourceConfiguration,
    "onedata": OnedataFileSourceConfiguration,
    "webdav": WebdavFileSourceConfiguration,
    "dropbox": DropboxFileSourceConfiguration,
    "googledrive": GoogleDriveFileSourceConfiguration,
    "crypt4gh_via_ssh": Crypt4ghSshFileSourceConfiguration,
}


OAUTH2_CONFIGURED_SOURCES: ConfiguredOAuth2Sources = {
    "dropbox": OAuth2Configuration(
        authorize_url="https://www.dropbox.com/oauth2/authorize",
        authorize_params={"token_access_type": "offline"},
        token_url="https://api.dropbox.com/oauth2/token",
    ),
    "googledrive": OAuth2Configuration(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        authorize_params={"access_type": "offline", "prompt": "consent"},
        token_url="https://oauth2.googleapis.com/token",
        scope="https://www.googleapis.com/auth/drive.file",
    ),
}

def get_oauth2_config(template: FileSourceTemplate) -> OAuth2Configuration:
    return get_oauth2_config_from(template, OAUTH2_CONFIGURED_SOURCES)


def get_oauth2_config_or_none(template: FileSourceTemplate) -> Optional[OAuth2Configuration]:
    if template.configuration.type not in OAUTH2_CONFIGURED_SOURCES:
        return None
    return get_oauth2_config(template)


def to_configuration_object(configuration_dict: Dict[str, Any]) -> FileSourceConfiguration:
    if "type" not in configuration_dict:
        raise KeyError("Configuration objects require a file source 'type' key, none found.")
    object_store_type = configuration_dict["type"]
    if object_store_type not in TypesToConfigurationClasses:
        raise ValueError(f"Unknown file source type found in raw configuration dictionary ({object_store_type}).")
    return TypesToConfigurationClasses[object_store_type](**configuration_dict)
```
Create lib/galaxy/files/sources/crypt4gh.py
```
import base64
import io
import os
from crypt4gh import keys
from crypt4gh.lib import decrypt

from typing import (
    Optional,
    Union,
)

from galaxy.files import OptionalUserContext
from . import (
    FilesSourceOptions,
    FilesSourceProperties,
)
from .ssh import SshFilesSource, SSHFS


class Crypt4ghViaSshFilesSource(SshFilesSource):
    plugin_type = "crypt4gh_via_ssh"

    def _open_fs(self, user_context=None, opts: Optional[FilesSourceOptions] = None):
        props = self._serialization_props(user_context)
        path = props.pop("path")
        self.sec_key = props.pop("sec_key")
        handle = self._get_root_handle(props, opts)
        if path:
            handle = handle.opendir(path)
        return handle

    def _get_root_handle(self, props, opts):
        extra_props: Union[FilesSourceProperties, dict] = opts.extra_props or {} if opts else {}
        return SSHFS(**{**props, **extra_props})

    def _realize_to(
        self,
        source_path: str,
        native_path: str,
        user_context: OptionalUserContext = None,
        opts: Optional[FilesSourceOptions] = None,
    ):
        with open(native_path, "wb") as write_file:
            props = self._serialization_props(user_context)
            _ = props.pop("path")
            sec_key_data = io.BytesIO(base64.b64decode(props.pop("sec_key")))
            assert sec_key_data.read(len(keys.c4gh.MAGIC_WORD)) == keys.c4gh.MAGIC_WORD
            parsed_sec_key = keys.c4gh.parse_private_key(sec_key_data, None)
            file_path = source_path.split("://")[-1].split("/", 1)[1]
            decrypt(
                [(0, parsed_sec_key, None)],
                self._get_root_handle(props, opts)._sftp.open(file_path),
                write_file
            )

    def _resource_info_to_dict(self, dir_path, resource_info):
        """Override to adjust filenames for display, removing the .c4gh suffix."""
        name = resource_info.name
        display_name = name[:-5] if name.endswith(".c4gh") else name
        path = os.path.join(dir_path, name)
        uri = self.uri_from_path(path)
        if resource_info.is_dir:
            return {"class": "Directory", "name": display_name, "uri": uri, "path": path}
        else:
            created = resource_info.created
            return {
                "class": "File",
                "name": display_name,
                "size": resource_info.size,
                "ctime": self.to_dict_time(created),
                "uri": uri,
                "path": path,
            }


all = ("Crypt4ghViaSshFilesSource",)
```

Now, your new template ega_outbox.yml should look like this:
```
- id: ega_live_outbox
  version: 0
  name: EGA Live Outbox Connection with transparent Crypt4gh decryption
  description: |
    This template allows connecting to the EGA Live Outbox. Requested data will be decrypted during download.
  configuration:
    type: crypt4gh_via_ssh
    host: "outbox.ega-archive.org"
    user: "{{ variables.user }}"
    port: 22
    path: "/outbox"
    passwd: "{{ secrets.password }}"
    sec_key: "{{ secrets.sec_key }}"
    writable: False
  variables:
    user:
      label: User
      type: string
      help: |
        Username to connect with.
  secrets:
    password:
      label: Password
      help: |
        Password to connect to SSH server with.
    sec_key:
      label: Crypt4gh private key
      help: |
        Your private key as generated with the crypt4gh tool for decryption of incoming data.
        Please do not provide any SSH key here.
        Only dedicated Crypt4gh keys are allowed with this Galaxy integration.
```
Add this file to the config/file_source_templates.yml so Galaxy can get this configuration.
```
#The path will vary depending of your development instance!
  - include: ".../galaxy/lib/galaxy/files/templates/examples/ega_outbox.yml"
```
As before, go to **Preferences -> Manage your Remote File Sources"** but this time create a EGA Outbox with Decryption. You will need your EGA username and your Crypt4gh private key.

![EGA OUTBOX](ega_out.jpg)

If this step goes well, you should be able to see your datasets decrypted after downloading:

![EGA decrypted](decrypt.jpg)
