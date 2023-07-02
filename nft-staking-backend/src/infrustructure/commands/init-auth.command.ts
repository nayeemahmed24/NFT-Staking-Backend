/* istanbul ignore file */
import { IsNotEmpty } from 'class-validator';

export class InitializeAuthCommand {
    @IsNotEmpty()
    public publicAddress: string;
}
