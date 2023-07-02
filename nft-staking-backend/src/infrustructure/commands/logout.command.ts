/* istanbul ignore file */
import { IsNotEmpty } from 'class-validator';

export class LogoutCommand {
    @IsNotEmpty()
    public publicAddress: string;

    @IsNotEmpty()
    public refreshToken: string;
}
