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


__all__ = ("Crypt4ghViaSshFilesSource",)
