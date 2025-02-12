/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

module.exports = function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    if (!toUrl) {
      res.status(400)
      return next(new Error('Missing target URL for redirect'))
    }

    // Only allow redirects to specific whitelisted URLs
    const allowedUrls = [
      'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
      'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
      'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
    ]

    if (allowedUrls.includes(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return allowedUrls.includes(toUrl) })
      res.redirect(toUrl)
    } else {
      res.status(403)
      next(new Error('Unauthorized redirect URL: ' + toUrl))
    }
  }
}
