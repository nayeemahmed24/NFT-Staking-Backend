import { Injectable, NestMiddleware } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class WalletAddressMiddleware implements NestMiddleware {
    constructor(private readonly jwtService: JwtService) {}
    use(req: Request, res: Response, next: NextFunction): any {
        let walletAddress;
        try {
            const authorizationHeaderValue = req.headers['authorization'];
            const token = authorizationHeaderValue.replace('Bearer ', '');
            const tokenInfo = this.jwtService.decode(token);
            walletAddress = tokenInfo['sub'];
        } catch (e) {}

        req.body['walletAddress'] = walletAddress;
        next();
    }
}
