import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { Roles } from 'src/iam/authorization/decorators/roles.decorator';
import { ActiveUser } from 'src/iam/decorators/active-user.decorator';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { Role } from 'src/users/enums/role.enum';
import { CreatePostcardDto } from './dto/create-postcard.dto';
import { UpdatePostcardDto } from './dto/update-postcard.dto';
import { PostcardsService } from './postcards.service';

@Controller('postcards')
export class PostcardsController {
  constructor(private readonly postcardsService: PostcardsService) {}

  @Roles(Role.Admin)
  @Post()
  create(@Body() createPostcardDto: CreatePostcardDto) {
    return this.postcardsService.create(createPostcardDto);
  }

  @Get()
  findAll(@ActiveUser() user: ActiveUserData) {
    console.log(user);
    return this.postcardsService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.postcardsService.findOne(+id);
  }

  @Roles(Role.Admin)
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updatePostcardDto: UpdatePostcardDto,
  ) {
    return this.postcardsService.update(+id, updatePostcardDto);
  }

  @Roles(Role.Admin)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.postcardsService.remove(+id);
  }
}
