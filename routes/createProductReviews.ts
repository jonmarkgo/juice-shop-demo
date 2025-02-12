/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import { reviewsCollection } from '../data/mongodb'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

module.exports = function productReviews () {
  return (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      res.status(401).json({ status: 'error', message: 'Unauthenticated user' })
      return
    }
    
    challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user && user.data.email !== req.body.author })
    
    const sanitizedReview = {
      product: security.sanitizeHtml(req.params.id),
      message: security.sanitizeHtml(req.body.message),
      author: user.data.email, // Ensure author is the authenticated user
      likesCount: 0,
      likedBy: []
    }
    
    reviewsCollection.insert(sanitizedReview).then(() => {
      res.status(201).json({ status: 'success' })
    }, (err: unknown) => {
      res.status(500).json(utils.getErrorMessage(err))
    })
  }
}
