/* istanbul ignore file */
import { IsNotEmpty } from 'class-validator';

export class LoginCommand {
    @IsNotEmpty()
    public publicAddress: string;

    @IsNotEmpty()
    public signature: string;

    @IsNotEmpty()
    public walletName: string;

    @IsNotEmpty()
    public networkName: string;

    @IsNotEmpty()
    public networkCurrencyName: string;
}
