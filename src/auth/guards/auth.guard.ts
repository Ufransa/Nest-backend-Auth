import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor ( 
    private jwtService: JwtService,
    private authService: AuthService ){}


  async canActivate( context: ExecutionContext ): Promise<boolean> {

    const request = context.switchToHttp().getRequest()
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('token not found');
    }

    try {


      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED }
    )

    const user = await this.authService.findUserById( payload.id )
    if ( !user ) throw new UnauthorizedException('user not found');
    if ( !user.isActive ) throw new UnauthorizedException('user not active');
    
    request['user'] = user


    } catch (e) {

      throw new UnauthorizedException('invalid token');

    }

    return true

  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
