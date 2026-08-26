import { Type } from "class-transformer";
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  ValidateNested,
} from "class-validator";

export class ChatMessageDto {
  @IsIn(["system", "user", "assistant", "tool"])
  role!: "system" | "user" | "assistant" | "tool";

  @IsString()
  @MaxLength(32_768)
  content!: string;
}

export class ChatCompletionDto {
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  model!: string;

  @IsArray()
  @ArrayMaxSize(64)
  @ValidateNested({ each: true })
  @Type(() => ChatMessageDto)
  messages!: ChatMessageDto[];

  @IsOptional()
  @IsBoolean()
  stream = false;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  session_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  purpose?: string;
}

export class ResponsesDto {
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  model!: string;

  @IsString()
  @MaxLength(32_768)
  input!: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  session_id?: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  purpose?: string;
}

export class ScanDto {
  @IsString()
  @MaxLength(32_768)
  text!: string;
}

export class TokenizeDto extends ScanDto {
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  session_id!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(128)
  purpose!: string;
}

export class RehydrateDto {
  @IsString()
  @MaxLength(180)
  token!: string;

  @IsString()
  @MaxLength(128)
  session_id!: string;

  @IsString()
  @MaxLength(128)
  purpose!: string;

  @IsString()
  @MaxLength(128)
  request_id!: string;

  @IsString()
  @MaxLength(32)
  policy_version!: string;
}

export class AttestationVerifyDto {
  @IsString()
  @MaxLength(256)
  nonce!: string;

  @IsString()
  @MaxLength(16_384)
  evidence!: string;
}

export class KeyLeaseDto {
  @IsBoolean()
  require_hardware_backed = true;
}
