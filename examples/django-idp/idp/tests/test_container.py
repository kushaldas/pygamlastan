"""Container process lifecycle regressions for the HTTP and recovery services."""
import subprocess
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from config import serve


class ContainerSupervisorTests(SimpleTestCase):
    """Keep delivery failures from silently leaving an HTTP-only container running."""

    def test_child_failure_stops_the_other_service(self):
        """Propagate a failed worker exit and terminate the still-running HTTP process."""
        worker = Mock()
        worker.poll.return_value = 7
        server = Mock()
        server.poll.return_value = None
        # Patch signal registration so this unit test does not alter the runner.
        with patch.object(serve.signal, "signal"), patch.object(serve.subprocess, "Popen", side_effect=[worker, server]):
            self.assertEqual(serve.main(["gunicorn", "config.wsgi:application"]), 7)
        server.terminate.assert_called_once()
        worker.wait.assert_called_once()
        server.wait.assert_called_once()

    def test_shutdown_kills_a_child_that_ignores_termination(self):
        """Bound shutdown time and reap a process that ignores its first signal."""
        worker = Mock()
        worker.poll.return_value = 0
        server = Mock()
        server.poll.return_value = None
        server.wait.side_effect = [subprocess.TimeoutExpired("gunicorn", 20), 0]
        with patch.object(serve.signal, "signal"), patch.object(serve.subprocess, "Popen", side_effect=[worker, server]):
            self.assertEqual(serve.main(["gunicorn", "config.wsgi:application"]), 1)
        server.terminate.assert_called_once()
        server.kill.assert_called_once()
        self.assertEqual(server.wait.call_count, 2)
