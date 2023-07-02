/* istanbul ignore file */
import { IsNotEmpty } from 'class-validator';

export class RefreshTokenCommand {
    @IsNotEmpty()
    public publicAddress: string;

    @IsNotEmpty()
    public refreshToken: string;
}
