# from localizationAnalysis import *
from measurementAnalysis import *

import pytest

from unittest.mock import patch, Mock
from types import SimpleNamespace
import responses
import pandas as pd
import pandas.testing as pdt

from localizationAnalysis import send_GETMeasurement_request

MODULE = "localizationAnalysis"


PCAP_NORMAL = "tests/test_files/normal.pcap"
NORMAL_SERVER_PORT = 49153

PCAP_NO_LOSS = "tests/test_files/noLoss.pcap"
NO_LOSS_SERVER_PORT = 49153

PCAP_ALL_LOSS = "tests/test_files/allLoss.pcap"
ALL_LOSS_SERVER_PORT = 49153


#==============================================HELPERS=================================================

# Copy pasted function from localizationAnalysis.py so that there are less conflicts with imports
def get_interval_sizes(min_rtt, duration, mult_start=10, mult_end=50, min_nb_intervals=30):
    interval_sizes = []
    for i in np.arange(mult_start, mult_end + 1, 1):
        if (duration / (min_rtt * i)) >= min_nb_intervals:
            interval_sizes.append(round(min_rtt * i, 3))
    return interval_sizes



def general_get_lossRatios_from_pcap(pcap_file, port):
    minRttsAndDurations = general_get_minRttAndDuration_from_pcap(pcap_file, port)
    interval_sizes = get_interval_sizes(minRttsAndDurations['minRtt'], minRttsAndDurations['duration'])
    assert len(interval_sizes) > 0, "No interval sizes computed, check minRtt and duration"
    
    lossRatios =  get_lossRatios_from_pcap(pcap_file, port, interval_sizes)
    print("Loss Ratios: ", lossRatios)
    return lossRatios

def general_get_minRttAndDuration_from_pcap(pcap_file, port):
    minRttsAndDurations = get_minRttAndDuration_from_pcap(pcap_file, port)
    
    assert minRttsAndDurations['minRtt'] > 0, "Min RTT is not greater than 0"
    assert minRttsAndDurations['duration'] > 0, "Duration is not greater than 0"
    return minRttsAndDurations

#==============================================LOSS RATIOS TESTS=================================================


# Test for lossRatios from pcap file, which succeeds
def test_get_lossRatios_from_pcap_normal():
    lossRatios = general_get_lossRatios_from_pcap(PCAP_NORMAL, NORMAL_SERVER_PORT)
    assert not lossRatios.empty, "Loss Ratios DataFrame is empty"
    
# Test for lossRatios from pcap file, which returns no loss
def test_get_lossRatios_from_pcap_noLoss():
    lossRatios = general_get_lossRatios_from_pcap(PCAP_NO_LOSS, NORMAL_SERVER_PORT)
    for lossRatio in lossRatios['perf']:
        assert lossRatio == 0, f"Expected lossRatio to be 0, got {lossRatio}"


# Test for lossRatios from pcap file
def test_get_lossRatios_from_pcap_allLost():
    lossRatios = general_get_lossRatios_from_pcap(PCAP_ALL_LOSS, NORMAL_SERVER_PORT)
    assert not lossRatios.empty, "Loss Ratios DataFrame is empty, expected lossRatios due to all packets lost"
    

#==============================================GET MEASUREMENT TESTS=================================================


DF_PAYLOAD = pd.DataFrame({"a": [1, 3], "b": [2, 4]})
RESULT_DICT = {"data": DF_PAYLOAD.values.tolist(), "columns": DF_PAYLOAD.columns.tolist()}
RESULT_TYPE = str(pd.DataFrame)

FAKE_SUCCESS = {
    "success": True,
    "measurements": {"result": RESULT_DICT, "resultType": RESULT_TYPE},
}
FAKE_FAIL = {"success": False, "error": "nothing"}


class DummySession:
    def __init__(self, payload):
        self.payload = payload
    def get(self, **kwargs):
        return Mock(text=json.dumps(self.payload))

# Test for GETMeasurement request with a successful response
def test_success_path():
    session = DummySession(FAKE_SUCCESS)
    out = send_GETMeasurement_request("1.2.3.4", {"a", 1}, port=1234, cert_file="cert.pem", session=session)
    pdt.assert_frame_equal(out.reset_index(drop=True), DF_PAYLOAD.reset_index(drop=True))
    
# Test for GETMeasurement request with a failure response
# This should return None, as the request is expected to fail.
def test_failure_path():
    session = DummySession(FAKE_FAIL)
    out =  send_GETMeasurement_request(
        "1.2.3.4", {},
        port="4443",
        cert_file="/does/not/matter",
        session=session,
    )
    assert out is None


# Integration test for GETMeasurement request
# This test requires a live server to respond correctly.
@responses.activate
def test_integration_GETMeasurement_success(monkeypatch, tmp_path):
    class DummyCfg:
        def get(self, key):
            return {"analyzer_tls_port": str(8443),
                    "certs_folder": str(tmp_path)}[key]
            
    monkeypatch.setattr(MODULE + ".Configs", DummyCfg)
    (tmp_path / "ca.crt").write_text("x")

    url = "https://127.0.0.1:8443/Results"
    responses.add(
        responses.GET,
        url,
        json={
            "success": True,
            "measurements": {"result": RESULT_DICT, "resultType": RESULT_TYPE},
        },
        status=200,
    )

    res = send_GETMeasurement_request("127.0.0.1", {})
    pdt.assert_frame_equal(res.reset_index(drop=True), DF_PAYLOAD.reset_index(drop=True))

# Integration test for GETMeasurement request
# This test requires a live server to crash safely when the socket on the other side is not up.
@responses.activate
def test_integration_GETMeasurement_fail(monkeypatch, tmp_path):
    class DummyCfg:
        def get(self, key):
            return {"analyzer_tls_port": str(8443),
                    "certs_folder": str(tmp_path)}[key]
            
    monkeypatch.setattr(MODULE + ".Configs", DummyCfg)
    (tmp_path / "ca.crt").write_text("x")

    res = send_GETMeasurement_request("127.0.0.1", {})
    assert res is None
