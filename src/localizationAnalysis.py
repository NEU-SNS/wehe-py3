import gevent.queue

from python_lib import *

logger = logging.getLogger('localization_analysis')

LOCq = gevent.queue.Queue()

def get_other_server_results(userID, historyCount, testID, serverIP):
    # send request for data
    measurements = None
    return measurements
def loc_analyzer(userID, historyCount, testID, data):
    ...
def loc_queue_processor(q):
    while True:
        userID, historyCount, testID, serverIP = q.get()
    ...

    measurements = get_server2_data(serverIP)
    loc_analyzer(userID, historyCount, testID, measurements)

class GetServerLocalizeRequestHandler(AnalyzerRequestHandler):


    @staticmethod
    def getCommandStr(): return "localize"

    @staticmethod
    def handleRequest(args):
        try:
            userID = args['userID'][0].decode('ascii', 'ignore')
            historyCount = int(args['historyCount'][0].decode('ascii', 'ignore'))
            testID = int(args['testID'][0].decode('ascii', 'ignore'))
            serverIP = args['serverIP'][0].decode('ascii', 'ignore')
        except KeyError as e:
            return json.dumps({'success': False, 'missing': str(e)})


        LOCq.put((userID, historyCount, testID, serverIP))







