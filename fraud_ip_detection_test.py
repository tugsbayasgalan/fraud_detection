import unittest
from fraud_ip_detection import *

class TestComputeDistance(unittest.TestCase):

    def test_same_input(self):
        distance = compute_distance((56.9, 56.8), (56.9, 56.8))
        self.assertTrue(distance == 0.0)
class TestFraudSetup(unittest.TestCase):

    def setUp(self):
        self.fd = FraudIpDetection('test_file.txt', 'acaea93a2d4b64')

    def test_entries(self):
        self.assertTrue(len(self.fd.data_map) == 2)

class TestScore(unittest.TestCase):

    def setUp(self):
        self.fd_basic = FraudIpDetection('test_file.txt', 'acaea93a2d4b64')
        self.fd_actual = FraudIpDetection('test_file_actual_address.txt', 'acaea93a2d4b64', True)

    def test_score_basic(self):
        score1 = self.fd_basic.score('8.8.8.8')
        score2 = self.fd_basic.score('22.4.62.188')
        self.assertTrue(score1 == 0.0)
        self.assertTrue(score2 == 0.0)

    def test_score_fraud_non_double(self):
        score_fraud = self.fd_basic.score('8.8.8.9')
        distance = compute_distance(self.fd_basic.get_loc_info('22.4.62.188'), self.fd_basic.get_loc_info('8.8.8.9'))
        self.assertTrue(distance == score_fraud)

    def test_score_fraud_actual(self):
        self.assertTrue(len(self.fd_actual.cache) == 2)
        self.assertTrue(len(self.fd_actual.data_map) == 2)
        score_fraud1 = self.fd_actual.score('159.122.100.42') #France is closer to Amsterdam
        score_fraud2 = self.fd_actual.score('1.1.0.255') #China is closer to Hong Kong
        self.assertTrue(score_fraud1[1] == 'FRAUD')
        self.assertTrue(score_fraud2[1] == 'LOGIN')


if __name__ == '__main__':
    unittest.main(verbosity=2)
