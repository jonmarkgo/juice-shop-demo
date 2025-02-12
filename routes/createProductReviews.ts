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
    challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user && user.data.email !== req.body.author })
    
    // Validate required fields
    if (!req.body.message || !req.body.author || typeof req.body.message !== 'string' || typeof req.body.author !== 'string') {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Invalid review data: message and author are required and must be strings'
      })
    }

    // Validate length constraints
    if (req.body.message.length > 1000 || req.body.author.length > 100) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid review data: message must be <= 1000 chars and author <= 100 chars'
      })
    }

    const sanitizedReview = {
      product: req.params.id,
      message: String(req.body.message).trim(),
      author: String(req.body.author).trim(),
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
