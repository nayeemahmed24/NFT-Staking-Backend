import { recoverPersonalSignature } from '@metamask/eth-sig-util';
import {
    BadRequestException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import { Request } from 'express';
import { StakingLogger } from '../logger/staking.logger';
import { JwtResponse } from 'src/infrustructure/authentication/jwt.response';
import { TokenTypeEnum } from 'src/infrustructure/enums/token.type.enum';
import { UserRoleEnum } from 'src/infrustructure/enums/user-role.enum';
import { LoginDto } from '../dtos/login.dto';
import { RefreshTokenDto } from '../dtos/refresh-token.dto';
import { TokenDto } from '../dtos/token.dto';
import { UserDto } from '../dtos/user.dto';
import { TokenService } from './token.service';
import { UserService } from './user.service';
import { JwtPayload } from 'src/infrustructure/authentication/jwt.payload';

let TTLInMilliseconds = 0;

@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly logger: StakingLogger,
        private readonly userService: UserService,
        private readonly tokenService: TokenService,
    ) {
        this.logger.setContext(AuthService.name);
        TTLInMilliseconds =
            this.configService.get<number>('JWT_EXPIRATION_TIME_SECONDS') *
            1000;
    }
    async initializeAuth(
        correlationId: string,
        accountAddress: string,
    ): Promise<JwtResponse> {
        this.logger.log(correlationId, 'initializeAuth START');
        const message = await this.generateMessage(correlationId);
        const payload = {
            sub: accountAddress,
            message: message,
            roles: [UserRoleEnum.Anonymous],
        };

        const anonymous_token = await this.jwtService.signAsync(
            payload,
            this.getJwtSignedOptions(TokenTypeEnum.AccessToken),
        );
        this.logger.log(correlationId, 'initializeAuth DONE');
        return {
            access_token: anonymous_token,
            refresh_token: null,
            message: message,
            expires_in: TTLInMilliseconds,
        };
    }

    async login(
        correlationId: string,
        authorizationHeaderValue: string,
        loginDto: LoginDto,
    ): Promise<JwtResponse> {
        this.logger.log(correlationId, 'login START');
        const { publicAddress, signature } = loginDto;

        this.logger.debug(
            correlationId,
            `given publicAddress: ${loginDto.publicAddress}, signature: ${loginDto.signature}`,
        );
        let recoveredAddr;
        const message = await this.getMessage(
            correlationId,
            authorizationHeaderValue,
            publicAddress,
        );
        try {
            recoveredAddr = recoverPersonalSignature({
                data: message,
                signature: signature,
            });
        } catch (err) {
            this.logger.error(correlationId, JSON.stringify(err));
            throw new BadRequestException(
                'Problem with signature verification.',
            );
        }

        this.logger.debug(
            correlationId,
            `recoveredAddr: ${recoveredAddr}, message: ${message}`,
        );

        if (recoveredAddr.toLowerCase() !== publicAddress.toLowerCase()) {
            this.logger.error(
                correlationId,
                'Signature is not correct. Public address not matched.',
            );
            throw new BadRequestException(
                'Signature is not correct. Public address not matched.',
            );
        }

        const refreshTokenPayload = {
            sub: publicAddress,
            message: message,
        };

        const refresh_token = await this.jwtService.signAsync(
            refreshTokenPayload,
            this.getJwtSignedOptions(TokenTypeEnum.RefreshToken),
        );

        const payload = {
            sub: publicAddress,
            message: message,
            roles: [UserRoleEnum.User],
        };

        const access_token = await this.jwtService.signAsync(
            payload,
            this.getJwtSignedOptions(TokenTypeEnum.AccessToken),
        );

        await this.addOrUpdateRefreshToken(
            access_token,
            refresh_token,
            publicAddress,
            correlationId,
        );

        await this.addOrUpdateUser(loginDto);

        this.logger.log(correlationId, 'login DONE');
        return {
            access_token: access_token,
            refresh_token: refresh_token,
            message: null,
            expires_in: TTLInMilliseconds,
        };
    }

    async logout(
        correlationId: string,
        accountAddress: string,
        refreshToken: string,
    ): Promise<string> {
        this.logger.log(correlationId, 'logout START');
        await this.tokenService.delete(
            correlationId,
            accountAddress,
            refreshToken,
        );
        this.logger.log(correlationId, 'logout DONE');
        return 'Success';
    }

    async logoutAllDevice(
        correlationId: string,
        accountAddress: string,
    ): Promise<string> {
        this.logger.log(correlationId, 'logoutAllDevice START');
        await this.tokenService.deleteAll(accountAddress);
        this.logger.log(correlationId, 'logoutAllDevice DONE');
        return 'Success';
    }

    async refresh(
        correlationId: string,
        refreshTokenDto: RefreshTokenDto,
    ): Promise<JwtResponse> {
        this.logger.log(correlationId, 'refresh START');
        const refresh_token = refreshTokenDto.refreshToken;
        const publicAddress = refreshTokenDto.publicAddress;
        let tokenPublicAddress = '';
        let expirationTime = 0;
        let message = '';

        try {
            const tokenInfo = this.jwtService.decode(refresh_token);
            tokenPublicAddress = tokenInfo['sub'];
            message = tokenInfo['message'];
            expirationTime = tokenInfo['exp'];
        } catch (err) {
            this.logger.error(correlationId, 'Refresh Token is not valid.');
            throw new UnauthorizedException('Refresh Token is not valid.');
        }

        const exp = new Date(expirationTime * 1000);
        this.logger.error(correlationId, exp);
        if (new Date() > exp) {
            await this.tokenService.delete(
                correlationId,
                publicAddress,
                refresh_token,
            );
            this.logger.error(correlationId, 'Refresh Token is expired.');
            throw new UnauthorizedException('Refresh Token is expired.');
        }

        if (tokenPublicAddress !== publicAddress) {
            this.logger.error(
                correlationId,
                'Token Public Address does not match with payload.',
            );
            throw new UnauthorizedException(
                'Token Public Address does not match with payload.',
            );
        }
        const token = await this.tokenService.getToken(
            publicAddress,
            refresh_token,
        );
        if (token === undefined || token === null) {
            this.logger.error(correlationId, 'Token is not available in DB.');
            throw new UnauthorizedException('Token is not available in DB.');
        }

        const refreshTokenPayload = {
            sub: publicAddress,
            message: message,
        };

        const new_refresh_token = await this.jwtService.signAsync(
            refreshTokenPayload,
            this.getJwtSignedOptions(TokenTypeEnum.RefreshToken),
        );

        const payload: JwtPayload = {
            sub: publicAddress,
            message: message,
            roles: [UserRoleEnum.User],
        };

        const new_access_token = await this.jwtService.signAsync(
            payload,
            this.getJwtSignedOptions(TokenTypeEnum.AccessToken),
        );

        const tokenDto: TokenDto = new TokenDto();
        tokenDto.access_token = new_access_token;
        tokenDto.refreshToken = new_refresh_token;
        tokenDto.publicAddress = publicAddress;
        try {
            const response = await this.tokenService.update(
                tokenDto,
                refresh_token,
            );
            if (response) {
                await this.userService.updateLastLoginDate(publicAddress);
                return {
                    access_token: new_access_token,
                    refresh_token: new_refresh_token,
                    message: null,
                    expires_in: TTLInMilliseconds,
                };
            }
            this.logger.log(correlationId, `Token is not available in DB.`);
            throw new UnauthorizedException('Token is not available in DB.');
        } catch (err) {
            this.logger.log(
                correlationId,
                `Error occured in time of refresh token update. ${err.message}`,
            );
            throw new UnauthorizedException(
                'Error occured in time of refresh token update.',
            );
        }
    }

    async addOrUpdateUser(loginDto: LoginDto) {
        const userDto: UserDto = new UserDto();
        userDto.publicAddress = loginDto.publicAddress;
        userDto.networkCurrencyName = loginDto.networkCurrencyName;
        userDto.networkName = loginDto.networkName;
        userDto.walletName = loginDto.walletName;
        userDto.signature = loginDto.signature;
        await this.userService.createOrUpdate(userDto);
    }

    // returns the secret message that was generated for an account address
    async getMessage(
        correlationId: string,
        authorizationHeaderValue: string,
        accountAddress: string,
    ): Promise<string> {
        this.logger.log(correlationId, 'getMessage START');

        let token = authorizationHeaderValue.replace('bearer ', '');
        token = authorizationHeaderValue.replace('Bearer ', '');

        const tokenInfo = this.jwtService.decode(token);
        const message = tokenInfo['message'];

        if (message === '' || message === null || message === undefined) {
            this.logger.error(
                correlationId,
                `NOT_FOUND/EXPIRED message against account address: ${accountAddress}`,
            );
            throw new BadRequestException(
                `NOT_FOUND/EXPIRED message against account address: ${accountAddress}`,
            );
        }

        this.logger.log(
            correlationId,
            `getMessage DONE and message = ${message}`,
        );
        return message;
    }

    private async addOrUpdateRefreshToken(
        access_token: string,
        refresh_token: string,
        publicAddress: string,
        correlationId: string,
    ) {
        const tokenDto: TokenDto = new TokenDto();
        tokenDto.access_token = access_token;
        tokenDto.refreshToken = refresh_token;
        tokenDto.publicAddress = publicAddress;
        const token = await this.tokenService.create(tokenDto);
        if (token === null) {
            await this.tokenService.deleteAll(publicAddress);
            this.logger.error(
                correlationId,
                'Refresh Token maximum limit exceeded for user.',
            );
            throw new BadRequestException(
                'Refresh Token maximum limit exceeded for user.',
            );
        }
    }

    getJwtSignedOptions(type: TokenTypeEnum): JwtSignOptions {
        const jwtTokenSecretKey =
            this.configService.get<string>('JWT_TOKEN_SECRET');
        const jwtTokenExpire = this.configService.get<number>(
            'JWT_EXPIRATION_TIME_SECONDS',
        );
        const jwtRefreshTokenSecretKey = this.configService.get<string>(
            'JWT_REFRESH_TOKEN_SECRET',
        );
        const jwtRefreshTokenExpire = this.configService.get<number>(
            'JWT_REFRESH_EXPIRATION_TIME_SECONDS',
        );

        if (type === TokenTypeEnum.AccessToken) {
            return {
                secret: jwtTokenSecretKey,
                expiresIn: jwtTokenExpire,
            };
        } else {
            return {
                secret: jwtRefreshTokenSecretKey,
                expiresIn: jwtRefreshTokenExpire,
            };
        }
    }

    async generateMessage(correlationId: string): Promise<string> {
        this.logger.log(correlationId, 'generateMessage START');
        return randomBytes(8).toString('hex');
    }

    public async validateSSO(
        correlationId: string,
        request: Request,
    ): Promise<{ message?: string; success: boolean; token?: JwtResponse }> {
        this.logger.log(correlationId, 'validateSSO Service STARTED');
        const hasCookies: { origin: string; access_token: string }[] = [];
        try {
            if (JSON.stringify(request?.cookies) === '{}') {
                return {
                    success: false,
                    message: 'Cookie unavailable',
                };
            }
            const ssoOriginStrings = this.configService.get(
                'SSO_ENABLED_DOMAINS',
            );
            this.logger.log(
                correlationId,
                `SSO enabled domain string: ${ssoOriginStrings}`,
            );
            const ssoAllowedOrigins = JSON.parse(ssoOriginStrings) || [];
            this.logger.log(
                correlationId,
                `SSO enabled domain array: ${JSON.stringify(
                    ssoAllowedOrigins,
                )}`,
            );
            this.logger.log(
                correlationId,
                `Caller domain: ${request?.headers.origin?.replace(
                    'https://',
                    '',
                )}`,
            );
            const domainAllowed = ssoAllowedOrigins?.find(
                (e) => e === request?.headers?.origin?.replace('https://', ''),
            );
            this.logger.log(
                correlationId,
                `Domain is allowed to call SSO: ${!!domainAllowed}`,
            );
            if (!domainAllowed) {
                this.logger.log(
                    correlationId,
                    'validateSSO Service ENDED Unsuccessfully',
                );
                return {
                    success: false,
                    message: 'Domain is not allowed for SSO',
                };
            }
            this.logger.log(
                correlationId,
                `Cookies: ${JSON.stringify(request?.cookies)}`,
            );
            for (const ssoOrigin of ssoAllowedOrigins) {
                const allowed = request?.cookies?.hasOwnProperty(ssoOrigin);
                if (allowed) {
                    const tmpToken = request?.cookies[ssoOrigin];
                    if (tmpToken) {
                        hasCookies.push({
                            origin: ssoOrigin,
                            access_token: request?.cookies[ssoOrigin],
                        });
                    }
                }
            }

            this.logger.log(
                correlationId,
                `Matched cookies Found: ${hasCookies.length}`,
            );

            if (!hasCookies || hasCookies.length <= 0) {
                this.logger.log(
                    correlationId,
                    'validateSSO Service ENDED Unsuccessfully, Cookie not found for any allowed domain',
                );
                return {
                    success: false,
                    message: 'Cookie not found for any allowed domain',
                };
            }
        } catch (err) {
            this.logger.error(
                correlationId,
                `validateSSO Service ENDED Unsuccessfully, ${err.message}`,
            );
            return {
                success: false,
                message: err.message,
            };
        }

        for (const cookie of hasCookies) {
            try {
                const tokenWalletAddress = await this.validateAccessToken(
                    correlationId,
                    cookie.access_token,
                );
                if (tokenWalletAddress) {
                    const refreshTokenAvailable =
                        await this.tokenService.getTokens(
                            tokenWalletAddress?.walletAddress,
                        );
                    if (
                        !refreshTokenAvailable ||
                        refreshTokenAvailable.length <= 0
                    ) {
                        continue;
                    }
                    return {
                        success: true,
                        token: await this.generateTokenForSSO(
                            correlationId,
                            tokenWalletAddress.walletAddress,
                            tokenWalletAddress.message,
                        ),
                    };
                }
            } catch (err) {
                this.logger.error(
                    correlationId,
                    `Exception occurred: ${err.message}`,
                );
            }
        }

        this.logger.log(
            correlationId,
            'validateSSO Service ENDED Unsuccessfully, No cookie token was valid.',
        );
        return {
            success: false,
            message: 'No cookie token was valid',
        };
    }

    private async generateTokenForSSO(
        correlationId: string,
        walletAddress: string,
        message: string,
    ): Promise<JwtResponse> {
        this.logger.log(
            correlationId,
            `generateTokenForSSO STARTED with walletAddress: ${walletAddress} and message: ${message}`,
        );
        const refreshTokenPayload = {
            sub: walletAddress,
            message: message,
        };

        const refresh_token = await this.jwtService.signAsync(
            refreshTokenPayload,
            this.getJwtSignedOptions(TokenTypeEnum.RefreshToken),
        );

        const payload: JwtPayload = {
            sub: walletAddress,
            message: message,
            roles: [UserRoleEnum.User],
        };

        const access_token = await this.jwtService.signAsync(
            payload,
            this.getJwtSignedOptions(TokenTypeEnum.AccessToken),
        );

        // await this.processUserCreateOrUpdate(loginDto);
        const existingUser = await this.userService.getUser(walletAddress);
        if (!existingUser) {
            this.logger.error(
                correlationId,
                `User doesn't exist with walletAddress: ${walletAddress}`,
            );
            return {
                access_token: null,
                refresh_token: null,
                message: `User doesn't exist with walletAddress: ${walletAddress}`,
                expires_in: null,
            };
        }

        await this.userService.updateLastLoginDate(walletAddress);
        await this.addOrUpdateRefreshToken(
            access_token,
            refresh_token,
            walletAddress,
            correlationId,
        );
        this.logger.log(
            correlationId,
            `generateTokenForSSO ENDED with walletAddress: ${walletAddress} and message: ${message}`,
        );
        return {
            access_token: access_token,
            refresh_token: refresh_token,
            message: null,
            expires_in: TTLInMilliseconds,
        };
    }

    private async validateAccessToken(correlationId: string, token: string) {
        this.logger.log(correlationId, `validateAccessToken STARTED`);
        const jwtTokenSecretKey =
            this.configService.get<string>('JWT_TOKEN_SECRET');
        try {
            const response = await this.jwtService.verifyAsync(token, {
                secret: jwtTokenSecretKey,
            });
            const tokenInfo = this.jwtService.decode(token);
            this.logger.log(
                correlationId,
                `Token validation is successful with response: ${JSON.stringify(
                    response,
                )}`,
            );

            const tokenPublicAddress = tokenInfo['sub'];
            const message = tokenInfo['message'];
            const expirationTime = tokenInfo['exp'];

            const exp = new Date(expirationTime * 1000);
            this.logger.error(correlationId, exp);
            if (new Date() > exp) {
                this.logger.error(correlationId, 'Refresh Token is expired.');
                return null;
            }
            this.logger.log(
                correlationId,
                `validateAccessToken ENDED with walletAddress: ${tokenPublicAddress} and message: ${message}`,
            );
            return {
                walletAddress: tokenPublicAddress,
                message: message,
            };
        } catch (err) {
            throw new UnauthorizedException(
                `Token is invalid with error: ${err}`,
            );
            return null;
        }
    }
}
