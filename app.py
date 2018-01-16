from __future__ import print_function
from chalice import Chalice, Response
import requests
import sys
import logging
import hmac
import json
import boto3


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

app = Chalice(app_name='webhookproxy')
# app.debug = True
# app.log.setLevel(logging.DEBUG)

# this is the name of the header from github
HTTP_X_HUB_SIGNATURE = 'X-Hub-Signature'

token = None
sharedkey = None
durl = None


@app.route('/hooky', methods=['POST'])
def deploy():
    # attach to iam client
    ssm = boto3.client('ssm')
    # default is to pull all from git
    whattoget = {'deploy-all': True}
    app.log.debug("in hooky")
    app.log.debug("raw body is ")
    # get raw_body as a str for debug
    raw_body_str = app.current_request.raw_body.decode('utf-8')
    app.log.debug(json.dumps(raw_body_str))
    # assume hmac is bad
    good_hmac = False
    # the header from git hub contains a signature
    if (HTTP_X_HUB_SIGNATURE in app.current_request.headers):
        # token is from "puppet-access login"
        para_t = ssm.get_parameter(Name='/nonprod/puppet/token')
        # shared key from the github settings hooks page
        para_s = ssm.get_parameter(Name='/nonprod/puppet/sharedkey')
        token = para_t['Parameter']['Value']
        para_u = ssm.get_parameter(Name='/nonprod/puppet/url')
        durl = "%s:8170/code-manager/v1/deploys" % para_u['Parameter']['Value']
        # convert sharedkey to bytes
        sharedkey = bytes(para_s['Parameter']['Value'], 'utf-8')
        # sig is from github
        sig = app.current_request.headers[HTTP_X_HUB_SIGNATURE]
        # ps is locally generated to prove signature is correct
        ps = hmac.new(sharedkey,
                      app.current_request.raw_body,
                      'sha1').hexdigest()
        computed = 'sha1=' + ps
        app.log.debug("supplied hmac: %s" % sig)
        app.log.debug("computed hmac: %s" % computed)
        # use special secure compare
        good_hmac = hmac.compare_digest(sig, computed)
    else:
        app.log.debug("NO HMAC HEADER")
    if (app.current_request.query_params is not None):
        # assume that only only branch is being pushed and try to optimise
        # to only pull this
        ref = app.current_request.query_params['ref']
        branch = ref.split('/')[-1]
        whattoget = {'environments': [branch]}
        app.log.debug("environment:%s" % branch)
    # good_hmac is True if github signature and locally generated are the same
    if (good_hmac):
        # timeout set by github is only 10 seconds, not enough to wait for
        # puppet pull
        payload = {'wait': False}
        payload.update(whattoget)
        # this passes the code manager "puppet-access login" token
        h = {'X-Authentication': token}
        r = requests.post(durl,            # deploy url
                          json=payload,    # commands
                          headers=h,       # authentication header
                          verify=False)    # ignore broke SSL
        app.log.debug("request to puppet code manager returns code %d" %
                      r.status_code)
        return Response(body='webhook',
                        status_code=r.status_code,
                        headers={'Content-Type': 'text/plain'})
    else:
        # because the hmac is bad, do a 403
        return Response(body='PERMISSION DENIED',
                        status_code=403,
                        headers={'Content-Type': 'text/plain'})
