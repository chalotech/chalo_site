#!/bin/bash

# Create temporary directory for frames
mkdir -p frames

# Generate 60 seconds of video at 30fps (1800 frames)
for i in $(seq -w 0 1799); do
    ffmpeg -f lavfi -i color=c=blue:s=1920x1080:d=1 \
           -vf "drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf:text='Welcome to Chalo Site':fontcolor=white:fontsize=80:x=(w-text_w)/2:y=(h-text_h)/2-50:alpha='if(lt(t,0.5),t/0.5,if(lt(t,2.5),1,if(lt(t,3),1-(t-2.5)/0.5,0)))':enable='between(t,0,3)', \
               drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf:text='Your One-Stop Shop for Digital Downloads':fontcolor=white:fontsize=40:x=(w-text_w)/2:y=(h-text_h)/2+50:alpha='if(lt(t,0.5),t/0.5,if(lt(t,2.5),1,if(lt(t,3),1-(t-2.5)/0.5,0)))':enable='between(t,0,3)', \
               format=yuv420p" \
           -frames:v 1 "frames/frame_${i}.png"
done

# Combine frames into video with fade transitions
ffmpeg -framerate 30 -pattern_type glob -i 'frames/*.png' \
       -c:v libx264 -pix_fmt yuv420p -crf 23 \
       -vf "colorbalance=bs=0.3:gs=0.3:rs=0.3, \
            drawbox=x=0:y=0:w=iw:h=ih:color=blue@0.3:t=fill, \
            gblur=sigma=3:steps=1" \
       -movflags +faststart \
       /home/chalo/chalo_site/static/videos/ad.mp4

# Clean up frames
rm -rf frames
