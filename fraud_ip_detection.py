import ipinfo
import math
import argparse
import sys
FRAUD = 'FRAUD'
LOGIN = 'LOGIN'

def compute_distance(ip_address_1, ip_address_2):

    #We will use Haversine formula to calculate the distance between two points

    #convert degrees to radians to be compatible with python math library
    lat1, long1 = math.radians(ip_address_1[0]), math.radians(ip_address_1[1])
    lat2, long2 = math.radians(ip_address_2[0]), math.radians(ip_address_2[1])

    #earth radius in miles
    R = 3959

    lat_difference = math.radians(lat2 - lat1)
    long_difference = math.radians(long2 - long1)

    #look at https://en.wikipedia.org/wiki/Haversine_formula for the formula
    a = math.sin(lat_difference/2)**2 + math.cos(lat1)*math.cos(lat2)*(math.sin(long_difference/2)**2)
    c = 2*math.asin(math.sqrt(a))
    distance = R*c
    #this is to output with 1 significant figure after decimal point
    return round(distance, 1)


class FraudIpDetection:

    def __init__(self, filePath, acc_token='acaea93a2d4b64'):

        self.filePath = filePath
        self.ip_handler = ipinfo.getHandler(acc_token)
        self.data_map = {}
        self.parse_data()

    def parse_data(self):
        with open(self.filePath) as f:
            for line in f:
                classification, ip_address = line.split()
                loc_info = self.get_loc_info(ip_address)
                self.data_map[ip_address] = {'classification': classification, 'loc': loc_info}

    def get_loc_info(self, ip_address):
        try:
            details = self.ip_handler.getDetails(ip_address)
            loc_info = details.loc
            latitude, longitude = loc_info.split(",")
            return (float(latitude), float(longitude))
        except Exception as e:
            raise Exception("Wrong input")

    def score(self, point):

        point_tuple = self.get_loc_info(point)
        distance, classification = self.find_closest(point_tuple)
        if classification == FRAUD:
            return distance*2
        return distance

    def find_closest(self, point_tuple):
        distance_array = [(compute_distance(point_tuple, self.data_map[i]['loc']),
                          self.data_map[i]['classification']) for i in self.data_map]
        return min(distance_array, key=lambda x: x[0])


def main(arguments):
    fraud_detector = FraudIpDetection(arguments['file_path'], arguments['access_token'])

    try:
        while True:
            user_input = raw_input("Provide an IP address: ")
            try:
                print fraud_detector.score(user_input)
            except:
                print "Something is wrong with the input. Please provide a valid IP address"
    except KeyboardInterrupt:
        print "Program is stopped by a user"
        sys.exit()

if __name__ == '__main__':

    parser = argparse.ArgumentParser('Please supply the file name and access token for ipinfo library')
    parser.add_argument('-f', '--file_path', help='Filepath for the fraud detector', required=True)
    parser.add_argument('-a', '--access_token', help='Access token for ipinfo', required=True)
    args = vars(parser.parse_args())
    main(args)
