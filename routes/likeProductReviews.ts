/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import { ObjectId } from 'mongodb'
import { sanitizeSecure } from '../lib/insecurity'

const security = require('../lib/insecurity')

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    let id: string
    try {
      id = sanitizeSecure(String(req.body.id))
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'Invalid review ID format' })
      }
    } catch (err) {
      return res.status(400).json({ error: 'Invalid review ID' })
    }
    
    const user = security.authenticatedUsers.from(req)
    const query = { _id: new ObjectId(id) }
    
    db.reviewsCollection.findOne(query).then((review: Review) => {
      if (!review) {
        res.status(404).json({ error: 'Not found' })
      } else {
        const likedBy = review.likedBy
        if (!likedBy.includes(user.data.email)) {
          db.reviewsCollection.update(
            query,
            { $inc: { likesCount: 1 } }
          ).then(
            () => {
              // Artificial wait for timing attack challenge
              setTimeout(function () {
                db.reviewsCollection.findOne(query).then((review: Review) => {
                  const likedBy = review.likedBy
                  likedBy.push(user.data.email)
                  let count = 0
                  for (let i = 0; i < likedBy.length; i++) {
                    if (likedBy[i] === user.data.email) {
                      count++
                    }
                  }
                  challengeUtils.solveIf(challenges.timingAttackChallenge, () => { return count > 2 })
                  db.reviewsCollection.update(
                    query,
                    { $set: { likedBy } }
                  ).then(
                    (result: any) => {
                      res.json(result)
                    }, (err: unknown) => {
                      res.status(500).json(err)
                    })
                }, () => {
                  res.status(400).json({ error: 'Wrong Params' })
                })
              }, 150)
            }, (err: unknown) => {
              res.status(500).json(err)
            })
        } else {
          res.status(403).json({ error: 'Not allowed' })
        }
      }
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
