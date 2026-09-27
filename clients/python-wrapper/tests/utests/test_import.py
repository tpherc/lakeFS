import time
from datetime import timedelta

import lakefs_sdk

from lakefs.exceptions import ImportManagerException
from lakefs.import_manager import ImportManager
from tests.utests.common import get_test_client, expect_exception_context


class TestImportManager:
    def test_import_start_wait(self, monkeypatch):
        clt = get_test_client()
        mgr = ImportManager("test_repo", "test_branch", client=clt)

        # Wait before start
        with expect_exception_context(ImportManagerException):
            mgr.wait()

        with monkeypatch.context():
            def monkey_import_start(*_, **__):
                return lakefs_sdk.ImportCreationResponse(id="import_id")

            monkeypatch.setattr(lakefs_sdk.ImportApi, "import_start", monkey_import_start)
            res = mgr.start()
            assert res == "import_id"

            # try again and expect import in progress
            with expect_exception_context(ImportManagerException):
                mgr.start()

            requests = 5
            status = lakefs_sdk.ImportStatus(completed=False,
                                             update_time=time.time(),
                                             ingested_objects=500,
                                             metarange_id=None,
                                             commit=None,
                                             error=None)

            def monkey_import_status(*_, **__):
                nonlocal requests, status
                requests -= 1
                if requests == 0:
                    status.completed = True
                return status

            monkeypatch.setattr(lakefs_sdk.ImportApi, "import_status", monkey_import_status)
            res = mgr.wait(poll_interval=timedelta())
            assert res.completed
            assert requests == 0

            # try again and expect no error
            mgr.wait()

    def test_mixed_sources_preserve_explicit_backends(self, monkeypatch):
        manager = ImportManager("repo", "main", client=get_test_client())
        manager.prefix("s3://raw/video/", "video/", storage_id="s3-source")
        manager.object("gs://metadata/record.json", "metadata.json", storage_id="gcs-source")
        manager.object("s3://home/legacy", "legacy")
        def start(*_, **kwargs):
            sources = kwargs["import_creation"].paths
            assert [source.storage_id for source in sources] == ["s3-source", "gcs-source", None]
            assert [source.type for source in sources] == ["common_prefix", "object", "object"]
            return lakefs_sdk.ImportCreationResponse(id="mixed-import")
        monkeypatch.setattr(lakefs_sdk.ImportApi, "import_start", start)
        assert manager.start() == "mixed-import"
