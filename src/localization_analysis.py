from python_lib import *

logger = logging.getLogger('localization_analysis')


class LocalizationAnalysis:

    def __init__(self, user_id, history_count, test_id, results_folder, attrs):
        LOG_ACTION(logger, 'Localization Analysis Running!')
