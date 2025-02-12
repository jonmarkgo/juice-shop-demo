/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'User not authenticated' })
    }
    
    if (!req.body.id || typeof req.body.id !== 'string' || !req.body.message) {
      return res.status(400).json({ error: 'Invalid input parameters' })
    }

    try {
      // First fetch the review to verify ownership
      const review = await db.reviewsCollection.findOne({ _id: req.body.id })
      if (!review) {
        return res.status(404).json({ error: 'Review not found' })
      }
      if (review.author !== user.data.email) {
        return res.status(403).json({ error: 'Not authorized to update this review' })
      }

      // Update only if user owns the review
      const result: { modified: number, original: Array<{ author: any }> } = await db.reviewsCollection.update(
        { _id: req.body.id, author: user.data.email },
        { $set: { message: req.body.message } },
        { multi: false }
      )

      challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 })
      challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 })
      res.json(result)
    } catch (err: unknown) {
      res.status(500).json(err)
    }
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
