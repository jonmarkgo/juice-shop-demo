/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Request, Response, NextFunction } from 'express'
import { Review } from '../data/types'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'

module.exports = function productReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'Invalid review ID' })
    }

    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    
    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy || []
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      await db.reviewsCollection.updateOne(
        { _id: id },
        { $inc: { likesCount: 1 } }
      )

      // Artificial wait for timing attack challenge
      await new Promise(resolve => setTimeout(resolve, 150))

      const updatedReview = await db.reviewsCollection.findOne({ _id: id })
      if (!updatedReview) {
        return res.status(404).json({ error: 'Review no longer exists' })
      }

      const updatedLikedBy = updatedReview.likedBy || []
      updatedLikedBy.push(user.data.email)

      let count = updatedLikedBy.filter((email: string) => email === user.data.email).length
      challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

      const result = await db.reviewsCollection.updateOne(
        { _id: id },
        { $set: { likedBy: updatedLikedBy } }
      )
      
      res.json(result)
    } catch (error) {
      next(error)
    }
  }
}
