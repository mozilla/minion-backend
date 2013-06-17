import unittest
from mock import MagicMock, Mock, patch

class TestBaseClass(unittest.TestCase):
    def setUp(self):
        self._mk1 = patch('minion.plugins.basic.BlockingPlugin')
        self._mk2 = patch('minion.curly.get')
        self._mk3 = patch('minion.plugins.basic.re')
        self._mk4 = patch('minion.plugins.basic.urlparse')

        self.mocks = []
        for i in xrange(1, 5):
            self.mocks.append(getattr(self, '_mk%s' % str(i)))

        self.mk_blocking = self._mk1.start()
        self.mk_curly = self._mk2.start()
        self.mk_re = self._mk3.start()
        self.mk_urlparse = self._mk4.start()

        # setup some magic mocks
        self.compile = MagicMock(name='re.compile')
        
        # setup some mocks
        self.mk_re.compile.return_value = self.compile
        self.configuration = {'target': 'http://localhost:1234'}

    def tearDown(self):
        for mk in self.mocks:
            mk.stop()

