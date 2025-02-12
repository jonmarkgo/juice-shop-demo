/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      let validatedUrl: string;
      try {
        // Validate URL protocol and domain
        const parsedUrl = new URL(req.body.imageUrl);
        const allowedProtocols = ['http:', 'https:'];
        
        if (!allowedProtocols.includes(parsedUrl.protocol)) {
          return next(new Error('Invalid URL protocol. Only HTTP and HTTPS are allowed.'));
        }

        // Check for internal network access attempts
        const blockedPatterns = [
          /^(localhost|127\.|0\.0\.0\.0|::1)/i,
          /^192\.168\./i,
          /^10\./i,
          /^172\.(1[6-9]|2[0-9]|3[0-1])\./i,
          /^fc00:/i
        ];
        
        if (blockedPatterns.some(pattern => pattern.test(parsedUrl.hostname))) {
          return next(new Error('Access to internal networks is not allowed'));
        }

        // Check if URL matches expected pattern for image files
        if (!req.body.imageUrl.match(/\.(jpg|jpeg|png|gif)$/i)) {
          return next(new Error('Invalid file type. Only jpg, jpeg, png, and gif files are allowed.'));
        }

        validatedUrl = parsedUrl.toString();
        
        // Keep SSRF detection for challenge
        if (validatedUrl.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
          req.app.locals.abused_ssrf_bug = true;
        }
      } catch (err) {
        return next(new Error('Invalid URL format'));
      }
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const imageRequest = request
          .get(validatedUrl)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: validatedUrl }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
              const ext = allowedExtensions.includes(validatedUrl.split('.').slice(-1)[0].toLowerCase()) ? validatedUrl.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: validatedUrl }) }).catch((error: Error) => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
