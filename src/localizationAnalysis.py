import json
import urllib.request

import gevent.queue

from python_lib import *

logger = logging.getLogger('localization_analysis')

LOCq = gevent.queue.Queue()

def get_peer_measurements(userID, historyCount, testID, serverIP):
    # send request for data
    data = {"userID": userID, "historyCount": historyCount, "testID": testID}
    body = json.dumps(data).encode()
    #need to add this to server
    request = urllib.request.Request(serverIP + '/requestLocStats', data=body)
    request.add_header("Content-Type", "application/json")

    response = urllib.request.urlopen(request)
    response.read().decode("utf-8")

    measurements = response
    return measurements

def loc_analyzer(userID, historyCount, testID, data):
    ...

class PostServerLocalizeRequestHandler(AnalyzerRequestHandler):

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
        except ValueError as e:
            return json.dumps({'success:': False, 'value error:': str(e)})

        LOCq.put((userID, historyCount, testID, serverIP))
        LOG_ACTION(logger, 'New localize job added to queue'.format(
            userID, historyCount, testID, serverIP))

        return json.dumps({'success': True})







